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
	"fmt"
	"strconv"
	"time"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Detect-and-heal for the meshnet new-node wiring race (AR-65093).
//
// On a freshly autoscaled node, a Cdnos/mcDNOS pod's CNI ADD can run before
// meshnet's CNI conflist is installed/ready on that node. When that happens the
// meshnet CNI plugin never runs for the pod, so the pod comes up with only the
// base CNI interface (eth0) and is permanently missing its meshnet data
// interfaces until it is recreated.
//
// Detection signal (low coupling, read-only): meshnet maintains a per-pod
// Topology CR (networkop.co.uk/v1beta1, named after the pod). Its spec.links is
// the authoritative set of interfaces meshnet must wire, and meshnet's CNI
// plugin calls SetAlive - which stamps status.net_ns / status.src_ip - at the
// very start of its ADD, before it traverses any link. Therefore an empty
// status.net_ns on a pod whose Topology has spec.links means "meshnet never ran
// for this pod", which is exactly the new-node race. A pod that is merely
// waiting for slow peers still has net_ns set, so this signal does not
// false-positive on normal wiring in progress.
//
// Heal: delete the under-wired pod. The normal reconcile path recreates it, so
// its CNI ADD re-runs once meshnet is ready and meshnet wires it normally.

const (
	healAttemptsAnnotation    = "meshnet.heal.cdnos.dev.drivenets.net/attempts"
	healLastAttemptAnnotation = "meshnet.heal.cdnos.dev.drivenets.net/last-attempt"
	healCappedAnnotation      = "meshnet.heal.cdnos.dev.drivenets.net/capped"

	healReasonRecreate = "MeshnetHealRecreate"
	healReasonCapped   = "MeshnetHealCapped"
)

// topologyGVK is the GroupVersionKind of meshnet's per-pod Topology CR. We read
// it as an unstructured object so the controller does not take a compile-time
// dependency on the meshnet module.
var topologyGVK = schema.GroupVersionKind{
	Group:   "networkop.co.uk",
	Version: "v1beta1",
	Kind:    "Topology",
}

// MeshnetHealConfig configures the meshnet detect-and-heal behaviour. The
// grace period, attempt cap, and backoff are the guardrails that keep a buggy
// or mistargeted heal from mass-deleting pods.
type MeshnetHealConfig struct {
	// Enabled turns the whole feature on/off.
	Enabled bool
	// GracePeriod is how long a pod must have been Running-but-under-wired
	// before we act, so we never race a pod that is still legitimately wiring.
	GracePeriod time.Duration
	// MaxAttempts bounds how many times we recreate a single pod before giving
	// up and emitting a Warning instead of looping forever.
	MaxAttempts int
	// Backoff is the minimum delay between successive heal attempts on the same
	// pod.
	Backoff time.Duration
}

// DefaultMeshnetHealConfig returns the default configuration. The feature
// defaults ON: the race leaves pods permanently stuck and requires manual
// recreation, and the grace period + attempt cap + backoff make the automated
// heal safe. Operators can disable it with --meshnet-heal-enabled=false.
func DefaultMeshnetHealConfig() MeshnetHealConfig {
	return MeshnetHealConfig{
		Enabled:     true,
		GracePeriod: 90 * time.Second,
		MaxAttempts: 3,
		Backoff:     60 * time.Second,
	}
}

// healDecision is the action decideHeal selects for an under-wired pod.
type healDecision int

const (
	// healWait means under-wired but still within the grace period or backoff;
	// re-check later.
	healWait healDecision = iota
	// healAct means recreate the pod now.
	healAct
	// healCapped means the per-pod attempt cap is exhausted; warn and stop.
	healCapped
)

// decideHeal is the pure decision core for an under-wired pod. It is split out
// from the k8s plumbing so it can be unit-tested exhaustively.
func decideHeal(now, runningSince, lastAttempt time.Time, attempts int, cfg MeshnetHealConfig) (healDecision, time.Duration) {
	if age := now.Sub(runningSince); age < cfg.GracePeriod {
		return healWait, cfg.GracePeriod - age
	}
	if attempts >= cfg.MaxAttempts {
		return healCapped, 0
	}
	if !lastAttempt.IsZero() {
		if since := now.Sub(lastAttempt); since < cfg.Backoff {
			return healWait, cfg.Backoff - since
		}
	}
	return healAct, 0
}

// meshnetWiring extracts, from a Topology CR, the number of links meshnet is
// expected to wire and whether meshnet has marked the pod alive (i.e. its CNI
// plugin ran). expected>0 && !wired is the AR-65093 under-wired signal.
func meshnetWiring(topo *unstructured.Unstructured) (expected int, wired bool) {
	links, _, _ := unstructured.NestedSlice(topo.Object, "spec", "links")
	expected = len(links)
	netNs, _, _ := unstructured.NestedString(topo.Object, "status", "net_ns")
	srcIP, _, _ := unstructured.NestedString(topo.Object, "status", "src_ip")
	wired = netNs != "" && srcIP != ""
	return expected, wired
}

// podRunningSince returns the time the pod's sandbox started, used as the
// anchor for the grace period.
func podRunningSince(pod *corev1.Pod) time.Time {
	if pod.Status.StartTime != nil {
		return pod.Status.StartTime.Time
	}
	return pod.CreationTimestamp.Time
}

// reconcileMeshnetHeal detects a Cdnos/mcDNOS pod that meshnet never wired
// (the new-node race) and heals it by recreating it. It is safe to call on
// every reconcile: it no-ops for non-meshnet pods, pods still within the grace
// period, healthy (wired) pods, and pods that have exhausted their attempt cap.
//
// Concurrency: controller-runtime serializes reconciles per Cdnos key, so the
// read-modify-write of the heal-accounting annotations on this Cdnos is safe
// without extra locking.
func (r *CdnosReconciler) reconcileMeshnetHeal(ctx context.Context, cdnos *cdnosv1.Cdnos, pod *corev1.Pod) (ctrl.Result, error) {
	if !r.MeshnetHeal.Enabled || pod == nil {
		return ctrl.Result{}, nil
	}
	log := log.FromContext(ctx)

	// Re-read the pod from the cache so we observe the current truth: a pod
	// that reconcilePod just created (Pending) or just deleted for a spec
	// change (NotFound / terminating) must not be touched here.
	fresh := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, fresh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if fresh.DeletionTimestamp != nil || fresh.Status.Phase != corev1.PodRunning {
		return ctrl.Result{}, nil
	}

	// Read the per-pod Topology CR directly from the API server (uncached: we
	// do not watch the meshnet CRD). NotFound means this is not a meshnet pod.
	topo := &unstructured.Unstructured{}
	topo.SetGroupVersionKind(topologyGVK)
	if err := r.APIReader.Get(ctx, types.NamespacedName{Name: fresh.Name, Namespace: fresh.Namespace}, topo); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	expected, wired := meshnetWiring(topo)
	if expected == 0 {
		return ctrl.Result{}, nil
	}
	if wired {
		// Healthy: clear any heal accounting so a future race on this Cdnos
		// starts with a fresh budget.
		return ctrl.Result{}, r.clearHealState(ctx, cdnos)
	}

	// Under-wired: meshnet never ran for this pod incarnation.
	now := time.Now()
	attempts, lastAttempt := readHealState(cdnos)
	decision, wait := decideHeal(now, podRunningSince(fresh), lastAttempt, attempts, r.MeshnetHeal)

	switch decision {
	case healWait:
		return ctrl.Result{RequeueAfter: wait}, nil

	case healCapped:
		if cdnos.Annotations[healCappedAnnotation] != "true" {
			msg := fmt.Sprintf("meshnet under-wired pod %s/%s not healed: 0/%d interfaces wired after %d attempts; manual intervention required",
				fresh.Namespace, fresh.Name, expected, attempts)
			log.Info(msg)
			r.event(cdnos, corev1.EventTypeWarning, healReasonCapped, msg)
			if err := r.patchHealAnnotations(ctx, cdnos, map[string]string{healCappedAnnotation: "true"}); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil

	case healAct:
		// Record the attempt BEFORE deleting so a crash between delete and the
		// next reconcile cannot drive an unbounded recreate loop.
		if err := r.patchHealAnnotations(ctx, cdnos, map[string]string{
			healAttemptsAnnotation:    strconv.Itoa(attempts + 1),
			healLastAttemptAnnotation: now.UTC().Format(time.RFC3339),
		}); err != nil {
			return ctrl.Result{}, err
		}
		msg := fmt.Sprintf("recreating under-wired Cdnos pod %s/%s: 0/%d meshnet interfaces wired (attempt %d/%d)",
			fresh.Namespace, fresh.Name, expected, attempts+1, r.MeshnetHeal.MaxAttempts)
		log.Info(msg)
		r.event(cdnos, corev1.EventTypeNormal, healReasonRecreate, msg)
		if err := r.Delete(ctx, fresh, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		// Re-check after the grace period to confirm the recreated pod wired.
		return ctrl.Result{RequeueAfter: r.MeshnetHeal.GracePeriod}, nil
	}

	return ctrl.Result{}, nil
}

// readHealState reads the per-Cdnos heal accounting from annotations.
func readHealState(cdnos *cdnosv1.Cdnos) (attempts int, lastAttempt time.Time) {
	if cdnos.Annotations == nil {
		return 0, time.Time{}
	}
	attempts, _ = strconv.Atoi(cdnos.Annotations[healAttemptsAnnotation])
	if v := cdnos.Annotations[healLastAttemptAnnotation]; v != "" {
		lastAttempt, _ = time.Parse(time.RFC3339, v)
	}
	return attempts, lastAttempt
}

// patchHealAnnotations merges the given annotations onto the Cdnos.
func (r *CdnosReconciler) patchHealAnnotations(ctx context.Context, cdnos *cdnosv1.Cdnos, kv map[string]string) error {
	patch := client.MergeFrom(cdnos.DeepCopy())
	if cdnos.Annotations == nil {
		cdnos.Annotations = map[string]string{}
	}
	for k, v := range kv {
		cdnos.Annotations[k] = v
	}
	return r.Patch(ctx, cdnos, patch)
}

// clearHealState removes all heal-accounting annotations if any are present.
func (r *CdnosReconciler) clearHealState(ctx context.Context, cdnos *cdnosv1.Cdnos) error {
	if cdnos.Annotations == nil {
		return nil
	}
	_, hasAttempts := cdnos.Annotations[healAttemptsAnnotation]
	_, hasLast := cdnos.Annotations[healLastAttemptAnnotation]
	_, hasCapped := cdnos.Annotations[healCappedAnnotation]
	if !hasAttempts && !hasLast && !hasCapped {
		return nil
	}
	patch := client.MergeFrom(cdnos.DeepCopy())
	delete(cdnos.Annotations, healAttemptsAnnotation)
	delete(cdnos.Annotations, healLastAttemptAnnotation)
	delete(cdnos.Annotations, healCappedAnnotation)
	return r.Patch(ctx, cdnos, patch)
}

// event records a k8s Event on the Cdnos if a recorder is configured.
func (r *CdnosReconciler) event(cdnos *cdnosv1.Cdnos, eventType, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(cdnos, eventType, reason, msg)
	}
}
