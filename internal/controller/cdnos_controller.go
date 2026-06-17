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
	"sort"
	"strings"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerruntime "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CdnosReconciler reconciles a Cdnos object
type CdnosReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIReader client.Reader
	// Recorder emits k8s Events (e.g. for meshnet detect-and-heal).
	Recorder record.EventRecorder
	// MaxConcurrentReconciles controls the number of concurrent reconciles.
	// If <= 0, controller-runtime's default (1) is used.
	MaxConcurrentReconciles int
	// MeshnetHeal configures detect-and-heal for the meshnet new-node wiring
	// race (AR-65093).
	MeshnetHeal MeshnetHealConfig
}

//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods;services;secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networkop.co.uk,resources=topologies,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Cdnos object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.16.3/pkg/reconcile
func (r *CdnosReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	cdnos := &cdnosv1.Cdnos{}

	if err := r.Get(ctx, req.NamespacedName, cdnos); err != nil {
		if apierrors.IsNotFound(err) {
			// Normal path on delete: owned objects are garbage-collected via
			// owner references, nothing for us to do.
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch Cdnos")
		return ctrl.Result{}, err
	}

	secret, err := r.reconcileSecrets(ctx, cdnos)
	if err != nil {
		log.Error(err, "unable to get reconcile secret")
		return ctrl.Result{}, err
	}
	var secretName string
	if secret != nil {
		secretName = secret.GetName()
		_ = secretName
	}

	// Ensure per-instance ServiceAccount and RBAC for querying services
	if _, err := r.reconcileRBAC(ctx, cdnos); err != nil {
		log.Error(err, "unable to reconcile rbac")
		return ctrl.Result{}, err
	}

	pod, err := r.reconcilePod(ctx, cdnos, secretName)
	if err != nil {
		log.Error(err, "unable to get reconcile pod")
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, cdnos); err != nil {
		log.Error(err, "unable to reconcile service")
		return ctrl.Result{}, err
	}

	var desiredPhase cdnosv1.CdnosPhase
	switch pod.Status.Phase {
	case corev1.PodRunning:
		desiredPhase = cdnosv1.Running
	case corev1.PodFailed:
		desiredPhase = cdnosv1.Failed
	default:
		desiredPhase = cdnosv1.Unknown
	}
	desiredMessage := fmt.Sprintf("Pod Details: %s", pod.Status.Message)

	if cdnos.Status.Phase != desiredPhase || cdnos.Status.Message != desiredMessage {
		patch := client.MergeFrom(cdnos.DeepCopy())
		cdnos.Status.Phase = desiredPhase
		cdnos.Status.Message = desiredMessage
		if err := r.Status().Patch(ctx, cdnos, patch); err != nil {
			log.Error(err, "unable to patch cdnos status")
			return ctrl.Result{}, err
		}
	}

	// Detect-and-heal the meshnet new-node wiring race (AR-65093): recreate a
	// pod that meshnet never wired so its CNI ADD re-runs once meshnet is ready.
	healResult, err := r.reconcileMeshnetHeal(ctx, cdnos, pod)
	if err != nil {
		log.Error(err, "unable to reconcile meshnet heal")
		return ctrl.Result{}, err
	}

	log.V(1).Info("Cdnos reconciled", "Name", cdnos.Name, "Image", cdnos.Spec.Image, "Namespace", cdnos.Namespace)

	return healResult, nil
}

// This is the function that is responsible for creating the tls secret
func (r *CdnosReconciler) reconcileSecrets(ctx context.Context, cdnos *cdnosv1.Cdnos) (*corev1.Secret, error) {
	log := log.FromContext(ctx)
	secretName := fmt.Sprintf("%s-tls", cdnos.Name)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cdnos.Namespace,
		},
	}
	err := r.Get(ctx, client.ObjectKeyFromObject(secret), secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	if !apierrors.IsNotFound(err) {
		if cdnos.Spec.TLS == nil || cdnos.Spec.TLS.SelfSigned == nil {
			log.Info("no tls config and secret exists, deleting it.")
			return nil, r.Delete(ctx, secret)
		}
		return secret, nil
	}

	if cdnos.Spec.TLS != nil && cdnos.Spec.TLS.SelfSigned != nil {
		if err := ctrl.SetControllerReference(cdnos, secret, r.Scheme); err != nil {
			return nil, err
		}
		cert, key, err := cert.GenerateSelfSignedCertKey(cdnos.Spec.TLS.SelfSigned.CommonName, nil, nil)
		if err != nil {
			return nil, err
		}
		secret.Data = map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
		}
		secret.Type = corev1.SecretTypeTLS
		log.Info("tls config not empty and secret doesn't exist, creating it.")
		return secret, r.Create(ctx, secret)
	}
	log.V(1).Info("no tls config and secret doesn't exist, doing nothing.")
	return nil, nil
}

const (
	secretMountPath = "/certs"
)

// NOTE: there used to be a package-level requiredArgs map here, declaring
// container args ("--enable_dataplane", "--alsologtostderr") that the
// controller would inject onto every cdnos pod if missing. That map and
// its consumer loop were removed because:
//
//  1. The consumer (`pod.Spec.Containers[0].Args = append(..., sortedArgs...)`)
//     was already commented out, so nothing was being injected.
//  2. The bookkeeping mutated the shared package-level map (`delete` per
//     observed arg) on every reconcile, which both raced across concurrent
//     reconciles and permanently drained the map after the first reconcile
//     that saw the args - meaning later Cdnos instances could never see
//     them either.
//
// If you need to default args on every cdnos pod again, do it per-reconcile
// (no shared mutable state), e.g. by merging a local slice into
// pod.Spec.Containers[0].Args inside reconcilePod, or - preferred - by
// surfacing the knob through CdnosSpec.Args so it is observable on the CR.

/*
This is the function that is responsible for the creation of the pod, including mounting the volumes
such as the tls secret,and the default volumes of /lib/modules and /core
*/
func (r *CdnosReconciler) reconcilePod(ctx context.Context, cdnos *cdnosv1.Cdnos, secretName string) (*corev1.Pod, error) {
	log := log.FromContext(ctx)
	pod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{Name: cdnos.Name, Namespace: cdnos.Namespace}, pod)
	var newPod bool
	var containerState corev1.ContainerState

	if apierrors.IsNotFound(err) {
		log.Info("new pod, creating initial spec")
		if err := r.setupInitialPod(pod, cdnos); err != nil {
			return nil, fmt.Errorf("failed to setup initial pod: %v", err)
		}
		newPod = true
	} else if err != nil {
		return nil, err
	}

	for _, containerStatus := range pod.Status.ContainerStatuses {
		log.V(1).Info("container status",
			"pod", pod.Name,
			"container", containerStatus.Name,
			"state", containerStatus.State,
			"ready", containerStatus.Ready,
			"restartCount", containerStatus.RestartCount,
			"image", containerStatus.Image,
		)
		containerState = containerStatus.State
	}

	// Check if model is explicitly set in labels, otherwise fall back to image name
	isMcdnosImage := false
	if model, ok := cdnos.Labels["model"]; ok && strings.ToUpper(model) == "MCDNOS" {
		isMcdnosImage = true
	} else {
		// Fall back to checking image name if model label is not set
		isMcdnosImage = strings.Contains(cdnos.Spec.Image, "mcdnos")
	}

	if containerState.Terminated != nil && !isMcdnosImage {
		log.Info("container exited, recreating pod", "pod", pod.Name)
		if err := r.Delete(ctx, pod, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
			return nil, err
		}
	}

	oldPodSpec := pod.Spec.DeepCopy()
	pod.Spec.Containers[0].Image = cdnos.Spec.Image
	pod.Spec.InitContainers[0].Image = cdnos.Spec.InitImage
	pod.Spec.InitContainers[0].Args = []string{fmt.Sprintf("%d", cdnos.Spec.InterfaceCount), fmt.Sprintf("%d", cdnos.Spec.InitSleep)}
	if isMcdnosImage {
		pod.Spec.Containers[0].Command = []string{"/sbin/init", "--log-level=err"}
		pod.Spec.Containers[0].Args = nil
		log.V(1).Info("mcdnos image detected", "command", pod.Spec.Containers[0].Command)
	} else if cdnos.Spec.Command != "" {
		pod.Spec.Containers[0].Command = []string{cdnos.Spec.Command}
		pod.Spec.Containers[0].Args = cdnos.Spec.Args
	} else {
		// Leave Command/Args nil so the container image's default
		// ENTRYPOINT/CMD is used.
		pod.Spec.Containers[0].Command = nil
		pod.Spec.Containers[0].Args = cdnos.Spec.Args
	}
	// Use a dedicated ServiceAccount per Cdnos for API access
	pod.Spec.ServiceAccountName = cdnos.Name
	pod.Spec.Containers[0].Env = cdnos.Spec.Env
	Limits := CombineResourceRequirements(cdnos.Labels, cdnos.Spec.Resources)
	pod.Spec.Containers[0].Resources = Limits
	if len(cdnos.Spec.NodeSelector) > 0 {
		pod.Spec.NodeSelector = cdnos.Spec.NodeSelector
		log.V(1).Info("applying nodeSelector to pod", "nodeSelector", cdnos.Spec.NodeSelector, "pod", pod.Name, "namespace", pod.Namespace)
	} else {
		pod.Spec.NodeSelector = nil
		log.V(1).Info("no nodeSelector specified, clearing pod nodeSelector", "pod", pod.Name, "namespace", pod.Namespace)
	}

	log.V(1).Info("cdnos env", "env", cdnos.Spec.Env)

	tspath := "/techsupport"
	corepath := "/core"
	redispath := "/redis"
	networdkpath := "/usr/lib/systemd/network"
	dockerpath := "/docker"

	mounts := map[string]corev1.VolumeMount{}
	volumes := map[string]corev1.Volume{}

	for _, vol := range pod.Spec.Volumes {
		volumes[vol.Name] = vol
	}
	for _, mount := range pod.Spec.Containers[0].VolumeMounts {
		mounts[mount.Name] = mount
	}

	// Add the volume mount unconditionally
	mounts["modules"] = corev1.VolumeMount{
		Name:      "modules",
		MountPath: "/lib/modules",
	}

	mounts["redis"] = corev1.VolumeMount{
		Name:      "redis",
		MountPath: redispath,
	}

	mounts["core"] = corev1.VolumeMount{
		Name:      "core",
		MountPath: corepath,
	}

	mounts["ts"] = corev1.VolumeMount{
		Name:      "ts",
		MountPath: tspath,
	}

	if isMcdnosImage {
		log.V(1).Info("mcdnos image detected", "image", cdnos.Spec.Image)
		mounts["networkd"] = corev1.VolumeMount{
			Name:      "networkd",
			MountPath: networdkpath,
		}
		mounts["docker"] = corev1.VolumeMount{
			Name:      "docker",
			MountPath: dockerpath,
		}

		// Map service account token into /tokens for MCDNOS
		mounts["tokens"] = corev1.VolumeMount{
			Name:      "tokens",
			MountPath: "/var/kubernetes/secrets/tokens",
			ReadOnly:  true,
		}
	}

	if cdnos.Spec.ConfigPath != "" && cdnos.Spec.ConfigFile != "" {
		log.V(1).Info("cdnos has a config", "name", cdnos.Name)
		configMapName := cdnos.Name + "-config"
		volumes["config"] = corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: configMapName,
					},
				},
			},
		}

		mounts["config"] = corev1.VolumeMount{
			Name:      "config",
			MountPath: cdnos.Spec.ConfigPath,
		}
	}

	// Define the volumes
	volumes["modules"] = corev1.Volume{
		Name: "modules",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/lib/modules",
			},
		},
	}

	volumes["redis"] = corev1.Volume{
		Name: "redis",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	volumes["core"] = corev1.Volume{
		Name: "core",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	volumes["ts"] = corev1.Volume{
		Name: "ts",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	if isMcdnosImage {
		volumes["networkd"] = corev1.Volume{
			Name: "networkd",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		}

		volumes["docker"] = corev1.Volume{
			Name: "docker",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		}

		// Project full service account files into /tokens for MCDNOS
		volumes["tokens"] = corev1.Volume{
			Name: "tokens",
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Path: "token",
							},
						},
						{
							DownwardAPI: &corev1.DownwardAPIProjection{
								Items: []corev1.DownwardAPIVolumeFile{
									{
										Path: "namespace",
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
						},
					},
				},
			},
		}
	}

	var changedMounts bool
	if _, ok := volumes["tls"]; secretName != "" && !ok {
		log.Info("adding tls secret to pod spec")
		volumes["tls"] = corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: secretName,
				},
			},
		}
		mounts["tls"] = corev1.VolumeMount{
			Name:      "tls",
			ReadOnly:  true,
			MountPath: secretMountPath,
		}
		changedMounts = true
	} else if secretName == "" && ok {
		delete(mounts, "tls")
		delete(volumes, "tls")
		changedMounts = true
	}

	// Only rebuild volumes/mounts when the TLS toggle actually changed the
	// set. At steady state we leave pod.Spec.Volumes/VolumeMounts as the
	// server returned them: any reorder of equivalent slices would defeat
	// equality.Semantic.DeepEqual (which does NOT treat slices as unordered)
	// and trigger spurious pod recreation. When we do rebuild, sort the
	// outputs by name so the rebuilt slice is deterministic across
	// reconciles even though the source is a Go map.
	if changedMounts {
		pod.Spec.Containers[0].VolumeMounts = sortedVolumeMounts(mounts)
		pod.Spec.Volumes = sortedVolumes(volumes)
	}

	if newPod {
		return pod, r.Create(ctx, pod)
	}

	if equality.Semantic.DeepEqual(oldPodSpec, &pod.Spec) {
		log.V(1).Info("pod unchanged, doing nothing")
		return pod, nil
	}
	log.Info("pod changed, deleting; recreate on next reconcile", "diff", cmp.Diff(*oldPodSpec, pod.Spec))
	// Pods are mostly immutable, so recreate them if the spec changed.
	// Use Background propagation: Foreground would have the apiserver wait
	// for dependents to be GC'd before the Pod object is removed, leaving
	// it in a "being deleted" state where our immediate Create would race
	// and lose with "object is being deleted". Background returns quickly;
	// the Pod's deletion event re-queues this Cdnos and the next reconcile
	// takes the newPod = true path and Creates a fresh Pod cleanly.
	if err := r.Delete(ctx, pod, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return pod, nil
}

func sortedVolumeMounts(m map[string]corev1.VolumeMount) []corev1.VolumeMount {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]corev1.VolumeMount, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func sortedVolumes(m map[string]corev1.Volume) []corev1.Volume {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]corev1.Volume, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// setupInitialPod creates the initial pod configuration for fields that don't change.
func (r *CdnosReconciler) setupInitialPod(pod *corev1.Pod, cdnos *cdnosv1.Cdnos) error {
	pod.ObjectMeta = metav1.ObjectMeta{
		Name:      cdnos.Name,
		Namespace: cdnos.Namespace,
		Labels: map[string]string{
			"app":  cdnos.Name,
			"topo": cdnos.Namespace,
		},
	}
	pod.Spec.InitContainers = []corev1.Container{{
		Name: "init",
	}}
	pod.Spec.Containers = []corev1.Container{{
		Name: "cdnos",
		SecurityContext: &corev1.SecurityContext{
			Privileged: pointer.Bool(true),
		},
	}}

	if err := ctrl.SetControllerReference(cdnos, pod, r.Scheme); err != nil {
		return err
	}
	return nil
}

// reconcileRBAC ensures a ServiceAccount, Role, and RoleBinding exist to allow the Cdnos pod
// to query Kubernetes Services in its namespace.
func (r *CdnosReconciler) reconcileRBAC(ctx context.Context, cdnos *cdnosv1.Cdnos) (string, error) {
	log := log.FromContext(ctx)
	saName := cdnos.Name
	roleName := fmt.Sprintf("%s-svc-reader", cdnos.Name)
	rbName := roleName
	commonLabels := map[string]string{
		"app":  cdnos.Name,
		"topo": cdnos.Namespace,
	}

	// ServiceAccount: Get-then-Create. The default client reads from the
	// informer cache so Get is essentially free; this avoids a guaranteed
	// AlreadyExists round-trip to the API server on every reconcile.
	var existingSA corev1.ServiceAccount
	err := r.Get(ctx, types.NamespacedName{Name: saName, Namespace: cdnos.Namespace}, &existingSA)
	switch {
	case apierrors.IsNotFound(err):
		sa := corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      saName,
				Namespace: cdnos.Namespace,
				Labels:    commonLabels,
			},
		}
		if err := ctrl.SetControllerReference(cdnos, &sa, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Create(ctx, &sa); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		log.Info("created serviceaccount", "name", saName)
	case err != nil:
		return "", err
	}

	// Role allowing restricted access to the Cdnos service in this namespace.
	// Limit to only getting the specific Service created for this Cdnos instance,
	// which is sufficient to read the MetalLB-assigned VIP from status.
	svcName := fmt.Sprintf("service-%s", cdnos.Name)
	desiredRules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"services"},
			ResourceNames: []string{svcName},
			Verbs:         []string{"get"},
		},
	}
	var existingRole rbacv1.Role
	err = r.Get(ctx, types.NamespacedName{Name: roleName, Namespace: cdnos.Namespace}, &existingRole)
	switch {
	case apierrors.IsNotFound(err):
		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleName,
				Namespace: cdnos.Namespace,
				Labels:    commonLabels,
			},
			Rules: desiredRules,
		}
		if err := ctrl.SetControllerReference(cdnos, &role, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Create(ctx, &role); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		log.Info("created role", "name", roleName)
	case err != nil:
		return "", err
	default:
		if !equality.Semantic.DeepEqual(existingRole.Rules, desiredRules) {
			existingRole.Rules = desiredRules
			if err := r.Update(ctx, &existingRole); err != nil {
				return "", err
			}
			log.Info("updated role rules", "name", roleName)
		}
	}

	// RoleBinding to bind the ServiceAccount to the Role
	var existingRB rbacv1.RoleBinding
	err = r.Get(ctx, types.NamespacedName{Name: rbName, Namespace: cdnos.Namespace}, &existingRB)
	switch {
	case apierrors.IsNotFound(err):
		rb := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: cdnos.Namespace,
				Labels:    commonLabels,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      saName,
					Namespace: cdnos.Namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     roleName,
			},
		}
		if err := ctrl.SetControllerReference(cdnos, &rb, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Create(ctx, &rb); err != nil && !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		log.Info("created rolebinding", "name", rbName)
	case err != nil:
		return "", err
	}

	return saName, nil
}

// Check if the given field name exists in the Env slice
func checkFieldExists(env []corev1.EnvVar, fieldName string) bool {
	for _, item := range env {
		if item.Name == fieldName {
			return true
		}
	}
	return false
}

// This is the function that is responsible for organizing the resource requirements and limits from the labels
func CombineResourceRequirements(kv map[string]string, req2 corev1.ResourceRequirements) corev1.ResourceRequirements {
	result := corev1.ResourceRequirements{
		Requests: map[corev1.ResourceName]resource.Quantity{},
		Limits:   map[corev1.ResourceName]resource.Quantity{},
	}

	if v, ok := kv["cpu"]; ok {
		result.Requests[corev1.ResourceCPU] = resource.MustParse(v)
	}

	if v, ok := kv["memory"]; ok {
		result.Requests[corev1.ResourceMemory] = resource.MustParse(v)
	}

	for name, quantity := range req2.Requests {
		result.Requests[name] = quantity.DeepCopy()
	}

	if v, ok := kv["cpu_limit"]; ok {
		result.Limits[corev1.ResourceCPU] = resource.MustParse(v)
	}

	if v, ok := kv["memory_limit"]; ok {
		result.Limits[corev1.ResourceMemory] = resource.MustParse(v)
	}

	for name, quantity := range req2.Limits {
		result.Limits[name] = quantity.DeepCopy()
	}

	return result
}

// This function is responsible for reconciling the service
func (r *CdnosReconciler) reconcileService(ctx context.Context, cdnos *cdnosv1.Cdnos) error {
	log := log.FromContext(ctx)
	var service corev1.Service
	svcName := fmt.Sprintf("service-%s", cdnos.Name)

	err := r.Get(ctx, types.NamespacedName{Name: svcName, Namespace: cdnos.Namespace}, &service)
	var newService bool
	if apierrors.IsNotFound(err) {
		service.ObjectMeta = metav1.ObjectMeta{
			Name:      svcName,
			Namespace: cdnos.Namespace,
			Labels: map[string]string{
				"name": cdnos.Name,
			},
		}
		service.Spec = corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			// MetalLB assigns the VIP from its IPAddressPool and does not
			// use the per-Service NodePort. Disabling NodePort allocation
			// removes the cluster's default ~2.7K NodePort cap (range
			// 30000-32767) as a scale ceiling and avoids hot-looping
			// "failed to allocate a nodePort: range is full" errors when
			// many Services exist.
			AllocateLoadBalancerNodePorts: pointer.Bool(false),
			Selector: map[string]string{
				"app":  cdnos.Name,
				"topo": cdnos.Namespace,
			},
		}
		if err := ctrl.SetControllerReference(cdnos, &service, r.Scheme); err != nil {
			return err
		}
		newService = true
	} else if err != nil {
		return err
	}

	oldSpec := service.Spec.DeepCopy()
	service.Spec.Ports = sortedServicePorts(cdnos.Spec.Ports)

	if len(cdnos.Spec.Ports) == 0 && newService {
		return nil
	}
	if len(cdnos.Spec.Ports) == 0 {
		return r.Delete(ctx, &service)
	}
	if newService {
		// Tolerate IsAlreadyExists from a concurrent reconcile worker
		// (or a previous reconcile of the same Cdnos racing the cache
		// refresh): the Service watch will re-queue us and the next
		// reconcile takes the Get + Update path.
		if err := r.Create(ctx, &service); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		return nil
	}
	if equality.Semantic.DeepEqual(oldSpec, &service.Spec) {
		log.V(1).Info("service unchanged, doing nothing")
		return nil
	}
	return r.Update(ctx, &service)
}

func sortedServicePorts(ports map[string]cdnosv1.ServicePort) []corev1.ServicePort {
	if len(ports) == 0 {
		return nil
	}
	names := make([]string, 0, len(ports))
	for name := range ports {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]corev1.ServicePort, 0, len(names))
	for _, name := range names {
		p := ports[name]
		out = append(out, corev1.ServicePort{
			Name:       name,
			Port:       p.OuterPort,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(int(p.InnerPort)),
		})
	}
	return out
}

// SetupWithManager sets up the controller with the Manager.
func (r *CdnosReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&cdnosv1.Cdnos{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{})
	if r.MaxConcurrentReconciles > 0 {
		b = b.WithOptions(controllerruntime.Options{MaxConcurrentReconciles: r.MaxConcurrentReconciles})
	}
	return b.Complete(r)
}
