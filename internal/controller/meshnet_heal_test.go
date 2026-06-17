/*
Copyright 2024 Drivenets

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strconv"
	"testing"
	"time"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestMeshnetWiring(t *testing.T) {
	tests := []struct {
		name         string
		links        []interface{}
		netNs        string
		srcIP        string
		wantExpected int
		wantWired    bool
	}{
		{
			name:         "no links is not a meshnet pod",
			links:        nil,
			wantExpected: 0,
			wantWired:    false,
		},
		{
			name:         "links but never wired (the race)",
			links:        []interface{}{map[string]interface{}{"local_intf": "eth1"}, map[string]interface{}{"local_intf": "eth2"}},
			netNs:        "",
			srcIP:        "",
			wantExpected: 2,
			wantWired:    false,
		},
		{
			name:         "links and wired",
			links:        []interface{}{map[string]interface{}{"local_intf": "eth1"}},
			netNs:        "/proc/123/ns/net",
			srcIP:        "10.0.0.1",
			wantExpected: 1,
			wantWired:    true,
		},
		{
			name:         "net_ns set but src_ip empty is not wired",
			links:        []interface{}{map[string]interface{}{"local_intf": "eth1"}},
			netNs:        "/proc/123/ns/net",
			srcIP:        "",
			wantExpected: 1,
			wantWired:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			topo := newTopology("r0", "ns", tc.links, tc.netNs, tc.srcIP)
			expected, wired := meshnetWiring(topo)
			if expected != tc.wantExpected {
				t.Errorf("expected=%d, want %d", expected, tc.wantExpected)
			}
			if wired != tc.wantWired {
				t.Errorf("wired=%v, want %v", wired, tc.wantWired)
			}
		})
	}
}

func TestDecideHeal(t *testing.T) {
	cfg := MeshnetHealConfig{Enabled: true, GracePeriod: 90 * time.Second, MaxAttempts: 3, Backoff: 60 * time.Second}
	now := time.Now()

	tests := []struct {
		name         string
		runningSince time.Time
		lastAttempt  time.Time
		attempts     int
		wantDecision healDecision
	}{
		{
			name:         "within grace period -> wait",
			runningSince: now.Add(-30 * time.Second),
			attempts:     0,
			wantDecision: healWait,
		},
		{
			name:         "past grace, first attempt -> act",
			runningSince: now.Add(-5 * time.Minute),
			attempts:     0,
			wantDecision: healAct,
		},
		{
			name:         "past grace but within backoff -> wait",
			runningSince: now.Add(-5 * time.Minute),
			lastAttempt:  now.Add(-10 * time.Second),
			attempts:     1,
			wantDecision: healWait,
		},
		{
			name:         "past grace, backoff elapsed -> act",
			runningSince: now.Add(-5 * time.Minute),
			lastAttempt:  now.Add(-2 * time.Minute),
			attempts:     1,
			wantDecision: healAct,
		},
		{
			name:         "attempts at cap -> capped",
			runningSince: now.Add(-5 * time.Minute),
			lastAttempt:  now.Add(-2 * time.Minute),
			attempts:     3,
			wantDecision: healCapped,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, wait := decideHeal(now, tc.runningSince, tc.lastAttempt, tc.attempts, cfg)
			if got != tc.wantDecision {
				t.Errorf("decision=%d, want %d", got, tc.wantDecision)
			}
			if got == healWait && wait <= 0 {
				t.Errorf("healWait should return a positive requeue delay, got %v", wait)
			}
		})
	}
}

func TestReadHealState(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)
	cdnos := &cdnosv1.Cdnos{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				healAttemptsAnnotation:    "2",
				healLastAttemptAnnotation: ts.Format(time.RFC3339),
			},
		},
	}
	attempts, last := readHealState(cdnos)
	if attempts != 2 {
		t.Errorf("attempts=%d, want 2", attempts)
	}
	if !last.Equal(ts) {
		t.Errorf("lastAttempt=%v, want %v", last, ts)
	}

	empty, zero := readHealState(&cdnosv1.Cdnos{})
	if empty != 0 || !zero.IsZero() {
		t.Errorf("empty cdnos: attempts=%d last=%v, want 0 and zero", empty, zero)
	}
}

// --- orchestration tests (fake client) ---

func TestReconcileMeshnetHeal_RecreatesUnderWiredPod(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-5*time.Minute))
	r, rec := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != r.MeshnetHeal.GracePeriod {
		t.Errorf("RequeueAfter=%v, want %v", res.RequeueAfter, r.MeshnetHeal.GracePeriod)
	}

	// Pod should have been deleted.
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected pod to be deleted, got err=%v", err)
	}

	// Attempt count recorded on the Cdnos.
	got := &cdnosv1.Cdnos{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, got); err != nil {
		t.Fatalf("get cdnos: %v", err)
	}
	if got.Annotations[healAttemptsAnnotation] != "1" {
		t.Errorf("attempts annotation=%q, want 1", got.Annotations[healAttemptsAnnotation])
	}
	if got.Annotations[healLastAttemptAnnotation] == "" {
		t.Errorf("last-attempt annotation not set")
	}
	assertEvent(t, rec, healReasonRecreate)
}

func TestReconcileMeshnetHeal_WiredPodClearsState(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "/proc/1/ns/net", "10.0.0.1", time.Now().Add(-5*time.Minute))
	markPodWired(pod)
	cdnos.Annotations = map[string]string{
		healAttemptsAnnotation:    "2",
		healLastAttemptAnnotation: time.Now().Format(time.RFC3339),
	}
	r, _ := newReconciler(cdnos, pod, topo)

	if _, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Pod must NOT be deleted.
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("wired pod should not be deleted, got err=%v", err)
	}
	got := &cdnosv1.Cdnos{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, got); err != nil {
		t.Fatalf("get cdnos: %v", err)
	}
	if _, ok := got.Annotations[healAttemptsAnnotation]; ok {
		t.Errorf("heal state should have been cleared, annotations=%v", got.Annotations)
	}
}

func TestReconcileMeshnetHeal_WithinGraceNoDelete(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-10*time.Second))
	r, _ := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a positive requeue while within grace, got %v", res.RequeueAfter)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("pod within grace must not be deleted, got err=%v", err)
	}
}

func TestReconcileMeshnetHeal_CapReachedWarns(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-5*time.Minute))
	cdnos.Annotations = map[string]string{
		healAttemptsAnnotation:    "3",
		healLastAttemptAnnotation: time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
	}
	r, rec := newReconciler(cdnos, pod, topo)

	if _, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pod must NOT be deleted once the cap is hit.
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("capped pod must not be deleted, got err=%v", err)
	}
	got := &cdnosv1.Cdnos{}
	_ = r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, got)
	if got.Annotations[healCappedAnnotation] != "true" {
		t.Errorf("capped annotation not set, annotations=%v", got.Annotations)
	}
	assertEvent(t, rec, healReasonCapped)
}

func TestReconcileMeshnetHeal_NotMeshnetPodNoop(t *testing.T) {
	cdnos, pod, _ := fixtures("r0", "ns", 0, "", "", time.Now().Add(-5*time.Minute))
	// No Topology object passed -> not a meshnet pod.
	r, _ := newReconciler(cdnos, pod)

	if _, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("non-meshnet pod must not be deleted, got err=%v", err)
	}
}

func TestReconcileMeshnetHeal_DisabledNoop(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-5*time.Minute))
	r, _ := newReconciler(cdnos, pod, topo)
	r.MeshnetHeal.Enabled = false

	if _, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("disabled feature must not delete pod, got err=%v", err)
	}
}

// An under-wired pod stuck in Pending/Init (KNE init-wait loops forever
// waiting for the missing interfaces) must heal after the grace period, since
// it never reaches Running.
func TestReconcileMeshnetHeal_PendingUnderWiredHealsAfterGrace(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-5*time.Minute))
	pod.Status.Phase = corev1.PodPending
	r, rec := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != r.MeshnetHeal.GracePeriod {
		t.Errorf("RequeueAfter=%v, want %v", res.RequeueAfter, r.MeshnetHeal.GracePeriod)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected under-wired Pending pod to be deleted, got err=%v", err)
	}
	got := &cdnosv1.Cdnos{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, got); err != nil {
		t.Fatalf("get cdnos: %v", err)
	}
	if got.Annotations[healAttemptsAnnotation] != "1" {
		t.Errorf("attempts annotation=%q, want 1", got.Annotations[healAttemptsAnnotation])
	}
	assertEvent(t, rec, healReasonRecreate)
}

// An under-wired Pending pod still within the grace period must not be touched
// (it may merely be starting up).
func TestReconcileMeshnetHeal_PendingWithinGraceNoDelete(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-10*time.Second))
	pod.Status.Phase = corev1.PodPending
	r, _ := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a positive requeue while within grace, got %v", res.RequeueAfter)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("Pending pod within grace must not be deleted, got err=%v", err)
	}
}

// A normally-starting pod that is still Pending (e.g. pulling its main
// container image) but whose init-wait has already completed - all expected
// interfaces are present - must never be healed, even past the grace period.
// This guards against deleting healthy pods that are simply still starting
// their containers.
func TestReconcileMeshnetHeal_PendingButWiredNoDelete(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 2, "/proc/1/ns/net", "10.0.0.1", time.Now().Add(-5*time.Minute))
	// init-wait completed (all interfaces wired) but the pod has not reached
	// Running yet because the main container is still starting.
	pod.Status.Phase = corev1.PodPending
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:  "init",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
	}}
	r, _ := newReconciler(cdnos, pod, topo)

	if _, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("wired (but still starting) pod must not be deleted, got err=%v", err)
	}
}

// Terminal pods (Succeeded/Failed) are never healed.
func TestReconcileMeshnetHeal_TerminalPodNoop(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		cdnos, pod, topo := fixtures("r0", "ns", 2, "", "", time.Now().Add(-5*time.Minute))
		pod.Status.Phase = phase
		r, _ := newReconciler(cdnos, pod, topo)

		res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
		if err != nil {
			t.Fatalf("phase %s: unexpected error: %v", phase, err)
		}
		if res.RequeueAfter != 0 {
			t.Errorf("phase %s: should not requeue, got %v", phase, res.RequeueAfter)
		}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
			t.Errorf("phase %s: terminal pod must not be deleted, got err=%v", phase, err)
		}
	}
}

// A PARTIALLY-wired pod (meshnet ran - net_ns set - but did not finish wiring
// every link, so init-wait is still blocking) must heal after the grace
// period. This is the AR-65093 50-node-scale case (n35/n37 stuck at 2/4): the
// old net_ns-only signal treated it as healthy and never recreated it.
func TestReconcileMeshnetHeal_PartialWiredHealsAfterGrace(t *testing.T) {
	// net_ns + src_ip set => meshnet ran; pod still Pending with init-wait
	// running => fewer than expected interfaces are present.
	cdnos, pod, topo := fixtures("r0", "ns", 4, "/proc/1/ns/net", "10.0.0.1", time.Now().Add(-5*time.Minute))
	r, rec := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != r.MeshnetHeal.GracePeriod {
		t.Errorf("RequeueAfter=%v, want %v", res.RequeueAfter, r.MeshnetHeal.GracePeriod)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected partially-wired pod to be deleted, got err=%v", err)
	}
	got := &cdnosv1.Cdnos{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, got); err != nil {
		t.Fatalf("get cdnos: %v", err)
	}
	if got.Annotations[healAttemptsAnnotation] != "1" {
		t.Errorf("attempts annotation=%q, want 1", got.Annotations[healAttemptsAnnotation])
	}
	assertEvent(t, rec, healReasonRecreate)
}

// A partially-wired pod still within the grace period must not be touched: it
// may merely be wiring behind a transiently-slow peer.
func TestReconcileMeshnetHeal_PartialWithinGraceSkip(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 4, "/proc/1/ns/net", "10.0.0.1", time.Now().Add(-10*time.Second))
	r, _ := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a positive requeue while within grace, got %v", res.RequeueAfter)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("partially-wired pod within grace must not be deleted, got err=%v", err)
	}
}

// A fully-wired pod (init-wait passed) must be a no-op even though its Topology
// may still carry stale status.skipped entries (which is why skipped is not
// used as the wired signal).
func TestReconcileMeshnetHeal_FullyWiredSkip(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 4, "/proc/1/ns/net", "10.0.0.1", time.Now().Add(-5*time.Minute))
	markPodWired(pod)
	// Stale skipped entries on an otherwise fully-wired pod must not trigger a heal.
	_ = unstructured.SetNestedSlice(topo.Object, []interface{}{
		map[string]interface{}{"link_id": int64(1), "pod_name": "peer"},
		map[string]interface{}{"link_id": int64(2), "pod_name": "peer"},
	}, "status", "skipped")
	r, _ := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("fully-wired pod should not requeue, got %v", res.RequeueAfter)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("fully-wired pod must not be deleted, got err=%v", err)
	}
}

// A pod whose Topology has no links (expected == 0) is not a wired meshnet pod
// and must be ignored even if it is stuck in init.
func TestReconcileMeshnetHeal_NoLinkSkip(t *testing.T) {
	cdnos, pod, topo := fixtures("r0", "ns", 0, "", "", time.Now().Add(-5*time.Minute))
	r, _ := newReconciler(cdnos, pod, topo)

	res, err := r.reconcileMeshnetHeal(context.Background(), cdnos, pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("no-link pod should not requeue, got %v", res.RequeueAfter)
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "r0", Namespace: "ns"}, &corev1.Pod{}); err != nil {
		t.Errorf("no-link pod must not be deleted, got err=%v", err)
	}
}

// --- helpers ---

func newTopology(name, ns string, links []interface{}, netNs, srcIP string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(topologyGVK)
	u.SetName(name)
	u.SetNamespace(ns)
	spec := map[string]interface{}{}
	if links != nil {
		spec["links"] = links
	}
	u.Object["spec"] = spec
	status := map[string]interface{}{}
	if netNs != "" {
		status["net_ns"] = netNs
	}
	if srcIP != "" {
		status["src_ip"] = srcIP
	}
	u.Object["status"] = status
	return u
}

// fixtures builds a Cdnos, an under-wired pod, and its Topology. By default the
// pod is modeled as under-wired: Pending with KNE's init-wait init container
// still Running (so podWiringComplete is false), which matches a pod stuck in
// Init:0/1. Tests that need a fully-wired pod call markPodWired.
func fixtures(name, ns string, nLinks int, netNs, srcIP string, startedAt time.Time) (*cdnosv1.Cdnos, *corev1.Pod, *unstructured.Unstructured) {
	cdnos := &cdnosv1.Cdnos{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       cdnosv1.CdnosSpec{InterfaceCount: nLinks},
	}
	start := metav1.NewTime(startedAt)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{InitContainers: []corev1.Container{{Name: "init"}}},
		Status: corev1.PodStatus{
			Phase:     corev1.PodPending,
			StartTime: &start,
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name:  "init",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	var links []interface{}
	for i := 0; i < nLinks; i++ {
		links = append(links, map[string]interface{}{"local_intf": "eth" + strconv.Itoa(i+1)})
	}
	topo := newTopology(name, ns, links, netNs, srcIP)
	return cdnos, pod, topo
}

// markPodWired marks the pod as fully wired (init-wait passed): it has reached
// Running with its init container terminated successfully.
func markPodWired(pod *corev1.Pod) {
	pod.Status.Phase = corev1.PodRunning
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:  "init",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
	}}
}

func newReconciler(objs ...client.Object) (*CdnosReconciler, *record.FakeRecorder) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = cdnosv1.AddToScheme(s)
	// Register the meshnet Topology CR as unstructured so the fake client can
	// track it without importing the meshnet module.
	s.AddKnownTypeWithName(topologyGVK, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(topologyGVK.GroupVersion().WithKind("TopologyList"), &unstructured.UnstructuredList{})

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	rec := record.NewFakeRecorder(10)
	return &CdnosReconciler{
		Client:      c,
		APIReader:   c,
		Scheme:      s,
		Recorder:    rec,
		MeshnetHeal: DefaultMeshnetHealConfig(),
	}, rec
}

func assertEvent(t *testing.T, rec *record.FakeRecorder, reason string) {
	t.Helper()
	select {
	case ev := <-rec.Events:
		if !contains(ev, reason) {
			t.Errorf("event %q does not contain reason %q", ev, reason)
		}
	case <-time.After(time.Second):
		t.Errorf("expected an event with reason %q, got none", reason)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
