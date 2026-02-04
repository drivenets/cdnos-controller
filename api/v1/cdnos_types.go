/*
Copyright 2024 Drivenets.

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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CdnosSpec defines the desired state of Cdnos
type CdnosSpec struct {
	// Image to use for the CDNOS container
	Image string `json:"image,omitempty"`
	// Command is the name of the executable to run.
	Command string `json:"command,omitempty"`
	// Args are the args to pass to the command.
	Args []string `json:"args,omitempty"`
	// Env are the environment variables to set for the container.
	// +listType=map
	// +listMapKey=name
	Env []corev1.EnvVar `json:"env,omitempty"`
	// Metadata labels describing the node.
	Labels map[string]string `json:"labels,omitempty"`
	// ConfigPath is the mount point for configuration inside the pod.
	ConfigPath string `json:"configPath,omitempty"`
	// ConfigFile is the default configuration file name for the pod.
	ConfigFile string `json:"configFile,omitempty"`
	// InitImage is the docker image to use as an init container for the pod.
	InitImage string `json:"initImage,omitempty"`
	// Ports are ports to create on the service.
	Ports map[string]ServicePort `json:"ports,omitempty"`
	// InterfaceCount is number of interfaces to be attached to the pod.
	// +optional
	InterfaceCount int `json:"interfaceCount"`
	// InitSleep is the time sleep in the init container
	// +optional
	InitSleep int `json:"initSleep"`
	// Resources are the K8s resources to allocate to cdnos container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`
	// TLS is the configuration the key/certs to use for management.
	// +optional
	TLS *TLSSpec `json:"tls"`
}

type TLSSpec struct {
	// SelfSigned generates a new self signed certificate.
	// +optional
	SelfSigned *SelfSignedSpec `json:"selfSigned"`
}

// SelfSignedSpec is the configuration to generate a self-signed cert.
type SelfSignedSpec struct {
	/// Common name to set in the cert.
	CommonName string `json:"commonName"`
	// RSA keysize to use for key generation.
	KeySize int `json:"keySize"`
}

// ServicePort describes an external L4 port on the device.
type ServicePort struct {
	// InnerPort is port on the container to expose.
	InnerPort int32 `json:"innerPort"`
	// OuterPort is port on the container to expose.
	OuterPort int32 `json:"outerPort"`
}

// CdnosPhase is the overall status of the Cdnos.
type CdnosPhase string

const (
	// Running indicates a successfully running cdnos.
	Running CdnosPhase = "Running"
	// Failed indicates an error state.
	Failed CdnosPhase = "Failed"
	// Unknown indicates an unknown state.
	Unknown CdnosPhase = "Unknown"
	// Pending indicates a pending state.
	Pending CdnosPhase = "Pending"
)

// CdnosStatus defines the observed state of Cdnos
type CdnosStatus struct {
	// Phase is the overall status of the Cdnos.
	Phase CdnosPhase `json:"phase"`
	// Message describes why the Cdnos is in the current phase.
	Message string `json:"message"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:path=cdnoss,singular=cdnos

// Cdnos is the Schema for the cdnos API
type Cdnos struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CdnosSpec   `json:"spec,omitempty"`
	Status CdnosStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CdnosList contains a list of Cdnos
type CdnosList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cdnos `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Cdnos{}, &CdnosList{})
}
