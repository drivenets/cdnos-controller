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

// Detect-and-heal for meshnet under-wiring (AR-65093).
//
// On a freshly autoscaled node, a Cdnos/mcDNOS pod can come up missing some or
// all of its meshnet data interfaces, and KNE's init-wait init container then
// blocks the pod in Init:0/1 forever (it loops until every expected interface
// is present). Two observed variants:
//
//   - Fully unwired (the new-node race): the pod's CNI ADD runs before meshnet's
//     CNI conflist is installed/ready on the node, so the meshnet CNI plugin
//     never runs and the pod has only eth0 (0 data interfaces).
//   - Partially wired (dead/slow-peer deadlock): meshnet ran but could not wire
//     every link because some peer pod was not alive yet, and that peer never
//     comes up healthy - so a subset of interfaces is permanently missing
//     (observed at 50-node scale: n35/n37 stuck at 2/4).
//
// Detection signal (low coupling, read-only): meshnet maintains a per-pod
// Topology CR (networkop.co.uk/v1beta1, named after the pod). Its spec.links is
// the authoritative set of interfaces meshnet must wire, so expected =
// len(spec.links). A pod is under-wired whenever fewer than expected interfaces
// are actually present.
//
// "Actual wired" signal: we do NOT trust Topology status.skipped as a wired
// count. status.skipped records links THIS pod skipped during its own CNI ADD
// (peer not yet alive); meshnet never clears it once the peer later wires the
// link from its side, so at scale most fully-healthy Running/Ready pods carry
// stale skipped entries (some 4/4). Keying on skipped would recreate the whole
// fleet. Instead we use KNE's init-wait init container as the ground-truth
// interface counter: init-wait blocks precisely until all expected interfaces
// exist, so a pod whose init containers have all completed (or that has reached
// Running) is fully wired, and a pod still stuck in init past the grace period
// is under-wired. status.net_ns / status.src_ip (stamped by meshnet's SetAlive
// at the very start of CNI ADD) are kept only to label the variant in
// logs/events: empty => meshnet never ran (fully unwired); set => meshnet ran
// but did not finish (partial).
//
// Heal: delete the under-wired pod. The normal reconcile path recreates it, so
// its CNI ADD re-runs - once meshnet is ready and peers are up - and meshnet
// wires it normally. Recreate is bounded (grace + attempt cap + backoff), so a
// pod that is merely mid-wiring behind a transiently-slow peer is protected by
// the grace period, and even an over-eager recreate is self-correcting and
// capped rather than a recreate loop.

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
// expected to wire (expected = len(spec.links)) and whether meshnet has marked
// the pod alive (ran), i.e. its CNI plugin started. ran is derived from
// status.net_ns / status.src_ip, which meshnet's SetAlive stamps at the very
// start of CNI ADD. ran distinguishes the fully-unwired variant (meshnet never
// ran) from the partial variant (meshnet ran but did not finish) for
// logging/events; the under-wired decision itself is made from the pod's
// init-wait completion (see podWiringComplete), not from ran.
func meshnetWiring(topo *unstructured.Unstructured) (expected int, ran bool) {
	links, _, _ := unstructured.NestedSlice(topo.Object, "spec", "links")
	expected = len(links)
	netNs, _, _ := unstructured.NestedString(topo.Object, "status", "net_ns")
	srcIP, _, _ := unstructured.NestedString(topo.Object, "status", "src_ip")
	ran = netNs != "" && srcIP != ""
	return expected, ran
}

// podWiringComplete reports whether the pod has all of its expected meshnet
// interfaces, using KNE's init-wait init container as the ground-truth
// interface counter. init-wait blocks until every expected interface is
// present, so:
//   - a pod that has reached Running (or Succeeded) has necessarily passed
//     init-wait and is fully wired; and
//   - a still-initializing pod is fully wired only once all of its init
//     containers have terminated successfully.
//
// A pod still in init (including one with no init-container status reported yet)
// is treated as not-yet-complete; the grace period below prevents that from
// false-positiving on pods that are merely still starting.
func podWiringComplete(pod *corev1.Pod) bool {
	switch pod.Status.Phase {
	case corev1.PodRunning, corev1.PodSucceeded:
		return true
	}
	if len(pod.Status.InitContainerStatuses) == 0 {
		return false
	}
	for _, s := range pod.Status.InitContainerStatuses {
		if s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 {
			return false
		}
	}
	return true
}

// underWiredDesc returns a human-readable description of the under-wired
// variant for logs/events. We cannot read the exact present-interface count
// from the API, so we describe the variant rather than print a precise N/expected.
func underWiredDesc(ran bool, expected int) string {
	if !ran {
		return fmt.Sprintf("meshnet never ran: 0/%d interfaces wired", expected)
	}
	return fmt.Sprintf("meshnet wiring incomplete: fewer than %d interfaces wired", expected)
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
	// that reconcilePod just deleted for a spec change (NotFound / terminating)
	// must not be touched here.
	fresh := &corev1.Pod{}
	if err := r.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, fresh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Skip terminating and terminal pods. We deliberately do NOT require
	// PodRunning: KNE's init-wait init container holds an under-wired mcDNOS
	// pod in Pending/Init indefinitely (it loops forever waiting for the
	// missing interfaces), so it never reaches Running. Acting on Pending is
	// safe because the under-wired signal is phase-independent: meshnet's CNI
	// plugin stamps status.net_ns via SetAlive at CNI ADD (sandbox creation),
	// before any init/main container runs - so a Pending pod with spec.links
	// and an empty status.net_ns definitively means meshnet never ran (the
	// race), not a pod that is merely still pulling/starting. The grace period
	// and bounded-attempts/backoff guardrails below still apply unchanged.
	if fresh.DeletionTimestamp != nil ||
		fresh.Status.Phase == corev1.PodSucceeded ||
		fresh.Status.Phase == corev1.PodFailed {
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

	expected, ran := meshnetWiring(topo)
	if expected == 0 {
		return ctrl.Result{}, nil
	}
	if podWiringComplete(fresh) {
		// Fully wired (init-wait passed): clear any heal accounting so a future
		// under-wiring on this Cdnos starts with a fresh budget.
		return ctrl.Result{}, r.clearHealState(ctx, cdnos)
	}

	// Under-wired: fewer than expected interfaces are present (init-wait is
	// still blocking). ran labels the variant: false => meshnet never ran
	// (fully unwired / new-node race); true => meshnet ran but did not finish
	// wiring all links (partial / dead-peer deadlock).
	now := time.Now()
	attempts, lastAttempt := readHealState(cdnos)
	decision, wait := decideHeal(now, podRunningSince(fresh), lastAttempt, attempts, r.MeshnetHeal)

	switch decision {
	case healWait:
		return ctrl.Result{RequeueAfter: wait}, nil

	case healCapped:
		if cdnos.Annotations[healCappedAnnotation] != "true" {
			msg := fmt.Sprintf("meshnet under-wired pod %s/%s not healed: %s after %d attempts; manual intervention required",
				fresh.Namespace, fresh.Name, underWiredDesc(ran, expected), attempts)
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
		msg := fmt.Sprintf("recreating under-wired Cdnos pod %s/%s: %s (attempt %d/%d)",
			fresh.Namespace, fresh.Name, underWiredDesc(ran, expected), attempts+1, r.MeshnetHeal.MaxAttempts)
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
