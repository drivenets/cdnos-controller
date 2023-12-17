/*
Copyright 2023 davnerson-dn, nhadar-dn.

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
	//"path/filepath"
	"sort"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
		if cdnos.Spec.TLS.SelfSigned == nil {
			log.Info("no tls config and secret exists, deleting it.")
			return nil, r.Delete(ctx, secret)
		}
		return secret, nil
	}

	if cdnos.Spec.TLS.SelfSigned != nil {
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

	if apierrors.IsNotFound(err) {
		log.Info("new pod, creating initial spec")
		if err := r.setupInitialPod(pod, cdnos); err != nil {
			return nil, fmt.Errorf("failed to setup initial pod: %v", err)
		}
		newPod = true
	} else if err != nil {
		return nil, err
	}

	oldPodSpec := pod.Spec.DeepCopy()

	pod.Spec.Containers[0].Image = cdnos.Spec.Image
	pod.Spec.InitContainers[0].Image = cdnos.Spec.InitImage
	pod.Spec.InitContainers[0].Args = []string{fmt.Sprintf("%d", cdnos.Spec.InterfaceCount), fmt.Sprintf("%d", cdnos.Spec.InitSleep)}
	pod.Spec.Containers[0].Command = []string{cdnos.Spec.Command}
	//pod.Spec.Containers[0].Args = append(cdnos.Spec.Args, fmt.Sprintf("--target=%s", cdnos.Name))
	//pod.Spec.Containers[0].Args = append(cdnos.Spec.Args, "1000")
	pod.Spec.Containers[0].Env = cdnos.Spec.Env
	pod.Spec.Containers[0].Resources = cdnos.Spec.Resources

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

	mounts["core"] = corev1.VolumeMount{
		Name:      "core",
		MountPath: "/core",
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

	volumes["core"] = corev1.Volume{
		Name: "core",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
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
