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
	"path/filepath"
	"time"

	//"path/filepath"
	"os"
	"sort"
	"strings"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CdnosReconciler reconciles a Cdnos object
type CdnosReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods;services;secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch
//+kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=get;list;watch

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
			log.Info("Cdnos resource not found; likely deleted, skipping")
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

	pod, err := r.reconcilePod(ctx, cdnos, secretName)
	if err != nil {
		lowerErr := strings.ToLower(err.Error())
		if apierrors.IsAlreadyExists(err) || strings.Contains(lowerErr, "already exists") || strings.Contains(lowerErr, "being deleted") {
			log.Info("pod exists or is being deleted; requeueing")
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		log.Error(err, "unable to get reconcile pod")
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, cdnos); err != nil {
		log.Error(err, "unable to get reconcile service")
		return ctrl.Result{}, err
	}

	switch pod.Status.Phase {
	case corev1.PodRunning:
		cdnos.Status.Phase = cdnosv1.Running
	case corev1.PodFailed:
		cdnos.Status.Phase = cdnosv1.Failed
	default:
		cdnos.Status.Phase = cdnosv1.Unknown
	}
	cdnos.Status.Message = fmt.Sprintf("Pod Details: %s", pod.Status.Message)
	if err := r.Status().Update(ctx, cdnos); err != nil {
		log.Error(err, "unable to update cdnos status")
		return ctrl.Result{}, err
	}

	// If pod is Pending and using HostPath /core, requeue quickly to allow event-based fallback to trigger
	if pod.Status.Phase == corev1.PodPending && podHasCoreHostPath(pod) {
		log.Info("pod pending with HostPath /core; requeueing to evaluate fallback")
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	log.Info("Cdnos reconciled", "Name", cdnos.Name, "Image", cdnos.Spec.Image, "Namespace", cdnos.Namespace)

	return ctrl.Result{}, nil
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
	log.Info("no tls config and secret doesn't exist, doing nothing.")
	return nil, nil
}

const (
	secretMountPath = "/certs"
)

// required args feature removed as unused

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

	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "cdnos" {
			containerState = cs.State
		}
		log.Info("container status", "name", cs.Name, "state", cs.State, "ready", cs.Ready, "restarts", cs.RestartCount, "image", cs.Image)
	}

	if containerState.Terminated != nil {
		log.Info("container terminated; deleting pod to recreate", "reason", containerState.Terminated.Reason)
		if err := r.Delete(ctx, pod, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
			return nil, err
		}
		return pod, r.tryCreatePodWithFallback(ctx, pod)
	}

	oldPodSpec := pod.Spec.DeepCopy()
	pod.Spec.Containers[0].Image = cdnos.Spec.Image
	pod.Spec.InitContainers[0].Image = cdnos.Spec.InitImage
	pod.Spec.InitContainers[0].Args = []string{fmt.Sprintf("%d", cdnos.Spec.InterfaceCount), fmt.Sprintf("%d", cdnos.Spec.InitSleep)}
	if cdnos.Spec.Command != "" {
		pod.Spec.Containers[0].Command = []string{cdnos.Spec.Command}
	}
	pod.Spec.Containers[0].Env = cdnos.Spec.Env
	Limits := CombineResourceRequirements(cdnos.Labels, cdnos.Spec.Resources)
	pod.Spec.Containers[0].Resources = Limits
	// Normalize empty resource lists to nil to avoid spurious diffs
	if pod.Spec.Containers[0].Resources.Limits != nil && len(pod.Spec.Containers[0].Resources.Limits) == 0 {
		pod.Spec.Containers[0].Resources.Limits = nil
	}

	// Assuming cdnos.Spec.Env is of type []corev1.EnvVar
	cdnosEnv := cdnos.Spec.Env
	// Ensure POD_NAME env var exists for subPathExpr expansion
	if !checkFieldExists(pod.Spec.Containers[0].Env, "POD_NAME") {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.name"},
			},
		})
	}

	// Specify the field name to check
	tsfieldName := "ALLOC_TS"
	corefieldName := "ALLOC_CORE"
	redisfieldName := "ALLOC_REDIS"
	tspath := "/techsupport"
	corepath := "/core"
	redispath := "/redis"

	// Check if the specified field exists in the Env slice
	if checkFieldExists(cdnosEnv, tsfieldName) {
		log.Info("env present", "name", tsfieldName)
		tspath = "/ts_vol"
	}
	if checkFieldExists(cdnosEnv, corefieldName) {
		corepath = "/core_vol"
	}
	if checkFieldExists(cdnosEnv, redisfieldName) {
		redispath = "/redis_vol"
		log.Info("env present", "name", redisfieldName)
	}

	// removed requiredArgs logic

	mounts := map[string]corev1.VolumeMount{}
	volumes := map[string]corev1.Volume{}

	for _, vol := range pod.Spec.Volumes {
		volumes[vol.Name] = vol
	}
	for _, mount := range pod.Spec.Containers[0].VolumeMounts {
		mounts[mount.Name] = mount
	}

	var changedMounts bool

	// Capture existing core volume/mount for change detection
	oldCoreVol, coreVolExists := volumes["core"]
	oldCoreMount, coreMountExists := mounts["core"]

	// Add the volume mount unconditionally
	mounts["modules"] = corev1.VolumeMount{
		Name:      "modules",
		MountPath: "/lib/modules",
	}

	mounts["redis"] = corev1.VolumeMount{
		Name:      "redis",
		MountPath: redispath,
	}

	useHostPathCore := hostCoreDirExists()
	var newCoreMount corev1.VolumeMount
	if useHostPathCore {
		newCoreMount = corev1.VolumeMount{
			Name:        "core",
			MountPath:   corepath,
			SubPathExpr: "$(POD_NAME)",
		}
	} else {
		newCoreMount = corev1.VolumeMount{
			Name:      "core",
			MountPath: corepath,
		}
	}
	// Detect mount changes
	if !coreMountExists || oldCoreMount.SubPathExpr != newCoreMount.SubPathExpr || oldCoreMount.MountPath != newCoreMount.MountPath {
		changedMounts = true
	}
	mounts["core"] = newCoreMount

	mounts["ts"] = corev1.VolumeMount{
		Name:      "ts",
		MountPath: tspath,
	}

	// Add the ConfigMap volume and volume mount if mentioned
	if cdnos.Spec.ConfigPath != "" && cdnos.Spec.ConfigFile != "" {
		log.Info("config present", "name", cdnos.Name)
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

		// Mount a single file if ConfigFile specified; otherwise mount whole directory
		if cdnos.Spec.ConfigFile != "" {
			mounts["config"] = corev1.VolumeMount{
				Name:      "config",
				MountPath: filepath.Join(cdnos.Spec.ConfigPath, cdnos.Spec.ConfigFile),
				SubPath:   cdnos.Spec.ConfigFile,
			}
		} else {
			mounts["config"] = corev1.VolumeMount{
				Name:      "config",
				MountPath: cdnos.Spec.ConfigPath,
			}
		}
	}

	// Define the volumes
	volumes["modules"] = corev1.Volume{
		Name: "modules",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/lib/modules", // Replace with the actual host path to the modules directory
			},
		},
	}

	volumes["redis"] = corev1.Volume{
		Name: "redis",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

	var newCoreVol corev1.Volume
	if useHostPathCore {
		// Use HostPath /core only if it exists (do not create parent)
		hostPathDir := corev1.HostPathDirectory
		coreHostPath := "/core"
		log.Info("configuring core volume to use HostPath", "hostPath", coreHostPath, "mountPath", corepath)
		newCoreVol = corev1.Volume{
			Name: "core",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: coreHostPath,
					Type: &hostPathDir,
				},
			},
		}
	} else {
		log.Info("/core not found in controller context; using EmptyDir for core volume", "mountPath", corepath)
		newCoreVol = corev1.Volume{
			Name: "core",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		}
	}
	// Detect volume changes
	if !coreVolExists || oldCoreVol.HostPath == nil || oldCoreVol.HostPath.Path != newCoreVol.HostPath.Path {
		changedMounts = true
	}
	volumes["core"] = newCoreVol

	// If kubelet reported FailedMount for HostPath /core on this pod, fallback to EmptyDir
	if hasCoreFailedMountEvent(ctx, r.Client, pod) {
		log.Info("Detected FailedMount for HostPath /core via events; falling back to EmptyDir for core volume")
		volumes["core"] = corev1.Volume{
			Name: "core",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		}
		// Remove subPath when falling back to EmptyDir
		mounts["core"] = corev1.VolumeMount{
			Name:      "core",
			MountPath: corepath,
		}
		changedMounts = true
	}

	// If the container is stuck waiting with hostPath/mount errors (likely /core doesn't exist), fallback to EmptyDir
	if containerState.Waiting != nil {
		waitingLower := strings.ToLower(containerState.Waiting.Reason + " " + containerState.Waiting.Message)
		if strings.Contains(waitingLower, "hostpath") || strings.Contains(waitingLower, "mount") || strings.Contains(waitingLower, "no such file") || strings.Contains(waitingLower, "not a directory") {
			log.Info("HostPath /core appears unavailable; falling back to EmptyDir for core volume")
			volumes["core"] = corev1.Volume{
				Name: "core",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			}
			// Remove subPath when falling back to EmptyDir
			newCoreMountFallback := corev1.VolumeMount{
				Name:      "core",
				MountPath: corepath,
			}
			mounts["core"] = newCoreMountFallback
			changedMounts = true
		}
	}

	volumes["ts"] = corev1.Volume{
		Name: "ts",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}

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
	// pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, "--tls_key_file", filepath.Join(secretMountPath, "tls.key"), "--tls_cert_file", filepath.Join(secretMountPath, "tls.crt"))

	// Ensure initial pod gets volumes/mounts applied
	if newPod {
		changedMounts = true
	}
	if changedMounts {
		pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{}
		pod.Spec.Volumes = []corev1.Volume{}
		// deterministically order mounts by name
		mountNames := make([]string, 0, len(mounts))
		for name := range mounts {
			mountNames = append(mountNames, name)
		}
		sort.Strings(mountNames)
		for _, name := range mountNames {
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, mounts[name])
		}
		// deterministically order volumes by name
		volumeNames := make([]string, 0, len(volumes))
		for name := range volumes {
			volumeNames = append(volumeNames, name)
		}
		sort.Strings(volumeNames)
		for _, name := range volumeNames {
			pod.Spec.Volumes = append(pod.Spec.Volumes, volumes[name])
		}
	}

	if newPod {
		return pod, r.tryCreatePodWithFallback(ctx, pod)
	}

	if equality.Semantic.DeepEqual(oldPodSpec, &pod.Spec) {
		log.Info("pod unchanged, doing nothing")
		return pod, nil
	}
	log.Info("pod changed, recreating", "diff", cmp.Diff(*oldPodSpec, pod.Spec))
	// Pods are mostly immutable, so recreate it if the spec changed.
	if err := r.Delete(ctx, pod, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
		return nil, err
	}
	return pod, r.tryCreatePodWithFallback(ctx, pod)
}

// tryCreatePodWithFallback attempts to create the Pod. If creation is forbidden or
// otherwise fails due to HostPath usage (common in clusters that disallow HostPath),
// it switches the "core" volume to EmptyDir (ephemeral) and retries once.
func (r *CdnosReconciler) tryCreatePodWithFallback(ctx context.Context, pod *corev1.Pod) error {
	log := log.FromContext(ctx)
	log.Info("creating pod with HostPath core volume")
	// Build a fresh object with clean metadata to avoid resourceVersion/UID issues
	safePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			Labels:          pod.Labels,
			Annotations:     pod.Annotations,
			OwnerReferences: pod.OwnerReferences,
		},
		Spec: *pod.Spec.DeepCopy(),
	}
	if err := r.Create(ctx, safePod); err != nil {
		lowerErr := strings.ToLower(err.Error())
		// If the pod already exists or is in the process of being deleted, this is expected; let caller requeue
		if apierrors.IsAlreadyExists(err) || strings.Contains(lowerErr, "already exists") || strings.Contains(lowerErr, "being deleted") {
			log.Info("pod exists or is being deleted; will requeue", "pod", safePod.Name)
			return err
		}
		log.Error(err, "failed to create pod with HostPath core volume")
		// Print detailed info about HostPath volumes and their mounts to identify which directory failed
		for _, v := range safePod.Spec.Volumes {
			if v.HostPath != nil {
				var mountPath, subPathExpr string
				for _, m := range safePod.Spec.Containers[0].VolumeMounts {
					if m.Name == v.Name {
						mountPath = m.MountPath
						subPathExpr = m.SubPathExpr
						break
					}
				}
				log.Info(
					"HostPath volume setup failed (debug)",
					"volume", v.Name,
					"hostPath", v.HostPath.Path,
					"mountPath", mountPath,
					"subPathExpr", subPathExpr,
				)
			}
		}
		// Detect HostPath-related rejections
		if apierrors.IsForbidden(err) || strings.Contains(strings.ToLower(err.Error()), "hostpath") {
			log.Info("falling back to EmptyDir for core volume due to HostPath restrictions")
			// Fallback: replace core HostPath with EmptyDir
			for i, v := range safePod.Spec.Volumes {
				if v.Name == "core" {
					safePod.Spec.Volumes[i] = corev1.Volume{
						Name: "core",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					}
					break
				}
			}
			// Retry once with EmptyDir
			log.Info("retrying pod creation with EmptyDir core volume")
			retryPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            safePod.Name,
					Namespace:       safePod.Namespace,
					Labels:          safePod.Labels,
					Annotations:     safePod.Annotations,
					OwnerReferences: safePod.OwnerReferences,
				},
				Spec: *safePod.Spec.DeepCopy(),
			}
			return r.Create(ctx, retryPod)
		}
		return err
	}
	log.Info("pod created successfully")
	return nil
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

// Check if the given field name exists in the Env slice
func checkFieldExists(env []corev1.EnvVar, fieldName string) bool {
	for _, item := range env {
		if item.Name == fieldName {
			return true
		}
	}
	return false
}

// hostCoreDirExists returns true if /core exists in the controller runtime environment.
// Note: This is a heuristic and may not reflect the node filesystem where the Pod will run.
func hostCoreDirExists() bool {
	if info, err := os.Stat("/core"); err == nil && info.IsDir() {
		return true
	}
	return false
}

// podHasCoreHostPath returns true if the pod has a volume named "core" with HostPath "/core" (indicating we are trying HostPath strategy)
func podHasCoreHostPath(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == "core" && v.HostPath != nil && v.HostPath.Path == "/core" {
			return true
		}
	}
	return false
}

// hasCoreFailedMountEvent checks pod events for FailedMount related to /core HostPath
func hasCoreFailedMountEvent(ctx context.Context, c client.Client, pod *corev1.Pod) bool {
	var evList corev1.EventList
	if err := c.List(ctx, &evList, client.InNamespace(pod.Namespace)); err != nil {
		return false
	}
	for _, e := range evList.Items {
		if e.InvolvedObject.UID != pod.UID {
			continue
		}
		msg := strings.ToLower(e.Message)
		reason := strings.ToLower(e.Reason)
		if strings.Contains(reason, "failedmount") || strings.Contains(msg, "failedmount") || strings.Contains(msg, "mountvolume.setup failed") {
			if strings.Contains(msg, "/core") && (strings.Contains(msg, "hostpath") || strings.Contains(msg, "not a directory") || strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist")) {
				return true
			}
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
	service.Spec.Ports = []corev1.ServicePort{}
	for name, p := range cdnos.Spec.Ports {
		service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{
			Name:       name,
			Port:       p.OuterPort,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(int(p.InnerPort)),
		})
	}
	if len(cdnos.Spec.Ports) == 0 && newService {
		return nil
	}
	if len(cdnos.Spec.Ports) == 0 {
		return r.Delete(ctx, &service)
	}
	if newService {
		return r.Create(ctx, &service)
	}

	return r.Update(ctx, &service)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CdnosReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cdnosv1.Cdnos{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
