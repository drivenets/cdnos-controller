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
	"strings"

	//"path/filepath"
	"sort"

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
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CdnosReconciler reconciles a Cdnos object
type CdnosReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIReader client.Reader
}

//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cdnos.dev.drivenets.net,resources=cdnoss/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods;services;secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

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
		log.Error(err, "unable to fetch Cdnos")
		return ctrl.Result{}, client.IgnoreNotFound(err)
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
		log.Error(err, "unable to get reconcile service: %v")
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

var requiredArgs = map[string]struct{}{
	"--enable_dataplane": {},
	"--alsologtostderr":  {},
}

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

	fmt.Printf("Container statuses for Pod %s:\n", pod.Name)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		fmt.Printf("- Name: %s\n", containerStatus.Name)
		fmt.Printf("  State: %+v\n", containerStatus.State)
		fmt.Printf("  Ready: %t\n", containerStatus.Ready)
		fmt.Printf("  Restart Count: %d\n", containerStatus.RestartCount)
		fmt.Printf("  Image: %s\n", containerStatus.Image)
		containerState = containerStatus.State
	}

	isMcdnosImage := strings.Contains(cdnos.Spec.Image, "mcdnos")

	if containerState.Terminated != nil && !isMcdnosImage {
		fmt.Printf("container exited, recreating")
		if err := r.Delete(ctx, pod, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil {
			return nil, err
		}
	}

	oldPodSpec := pod.Spec.DeepCopy()
	pod.Spec.Containers[0].Image = cdnos.Spec.Image
	pod.Spec.InitContainers[0].Image = cdnos.Spec.InitImage
	pod.Spec.InitContainers[0].Args = []string{fmt.Sprintf("%d", cdnos.Spec.InterfaceCount), fmt.Sprintf("%d", cdnos.Spec.InitSleep)}
	pod.Spec.Containers[0].Command = []string{cdnos.Spec.Command}
	if isMcdnosImage {
		pod.Spec.Containers[0].Command = []string{"/sbin/init", "--log-level=err"}
		log.Info("mcdnos image detected", "command", pod.Spec.Containers[0].Command)
	}
	// Use a dedicated ServiceAccount per Cdnos for API access
	pod.Spec.ServiceAccountName = cdnos.Name
	pod.Spec.Containers[0].Env = cdnos.Spec.Env
	Limits := CombineResourceRequirements(cdnos.Labels, cdnos.Spec.Resources)
	pod.Spec.Containers[0].Resources = Limits
	// Apply nodeSelector if specified
	if cdnos.Spec.NodeSelector != nil {
		pod.Spec.NodeSelector = cdnos.Spec.NodeSelector
	}

	// Assuming cdnos.Spec.Env is of type []corev1.EnvVar
	cdnosEnv := cdnos.Spec.Env
	fmt.Printf("cdnosEnv: %+v\n", cdnosEnv)

	// Specify the field name to check
	tspath := "/techsupport"
	corepath := "/core"
	redispath := "/redis"
	networdkpath := "/usr/lib/systemd/network"
	dockerpath := "/docker"

	for _, arg := range pod.Spec.Containers[0].Args {
		if _, ok := requiredArgs[arg]; ok {
			delete(requiredArgs, arg)
		}
	}
	sortedArgs := make([]string, 0, len(requiredArgs))
	for arg := range requiredArgs {
		sortedArgs = append(sortedArgs, arg)
	}
	sort.Strings(sortedArgs)
	// in case we dont need args remove this line
	//pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, sortedArgs...)

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
		log.Info("mcdnos image detected", "image", cdnos.Spec.Image)
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

	// Add the ConfigMap volume and volume mount if mentioned
	if cdnos.Spec.ConfigPath != "" && cdnos.Spec.ConfigFile != "" {
		fmt.Println(cdnos.Name, "has a config")
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
	if secretName != "" {
		//pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, "--tls_key_file", filepath.Join(secretMountPath, "tls.key"), "--tls_cert_file", filepath.Join(secretMountPath, "tls.crt"))
	}

	if changedMounts {
		pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{}
		pod.Spec.Volumes = []corev1.Volume{}
		for _, mount := range mounts {
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, mount)
		}
		for _, volume := range volumes {
			pod.Spec.Volumes = append(pod.Spec.Volumes, volume)
		}
	}

	if newPod {
		return pod, r.Create(ctx, pod)
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
	return pod, r.Create(ctx, pod)
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

	// ServiceAccount: try create first (avoids needing get/list permissions)
	sa := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: cdnos.Namespace,
			Labels: map[string]string{
				"app":  cdnos.Name,
				"topo": cdnos.Namespace,
			},
		},
	}
	if err := ctrl.SetControllerReference(cdnos, &sa, r.Scheme); err != nil {
		return "", err
	}
	if err := r.Create(ctx, &sa); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
	} else {
		log.Info("created serviceaccount", "name", saName)
	}

	// Role allowing restricted access to the Cdnos service in this namespace
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
	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: cdnos.Namespace,
			Labels: map[string]string{
				"app":  cdnos.Name,
				"topo": cdnos.Namespace,
			},
		},
		Rules: desiredRules,
	}
	if err := ctrl.SetControllerReference(cdnos, &role, r.Scheme); err != nil {
		return "", err
	}
	if err := r.Create(ctx, &role); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
	} else {
		log.Info("created role", "name", roleName)
	}

	// RoleBinding to bind the ServiceAccount to the Role
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: cdnos.Namespace,
			Labels: map[string]string{
				"app":  cdnos.Name,
				"topo": cdnos.Namespace,
			},
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
	if err := r.Create(ctx, &rb); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
	} else {
		log.Info("created rolebinding", "name", rbName)
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
