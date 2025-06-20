/*
Copyright 2022.

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

package v1beta1

import (
	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/service"
	"github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	// CloudKittyAPIContainerImage - default fall-back image for CloudKitty API
	CloudKittyAPIContainerImage = "quay.io/podified-master-centos9/cloudkitty-api:current-podified"
	// CloudKittyProcessorContainerImage - default fall-back image for CloudKitty Processor
	CloudKittyProcessorContainerImage = "quay.io/podified-master-centos9/cloudkitty-processor:current-podified"
	// CloudKittyDbSyncHash hash
	CloudKittyDbSyncHash = "ckdbsync"
)

// CloudKittySpec defines the desired state of CloudKitty
type CloudKittySpec struct {
	CloudKittySpecCore `json:",inline"`

	// +kubebuilder:validation:Required
	APIImage string `json:"apiImage"`

	// +kubebuilder:validation:Required
	ProcessorImage string `json:"processorImage"`
}

// CloudKittySpecCore defines the desired state of CloudKitty. This version is used by the OpenStackControlplane (no image parameters)
type CloudKittySpecCore struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=60
	// APITimeout for Apache
	APITimeout int `json:"apiTimeout"`

	// RabbitMQ instance name
	// Needed to request a transportURL that is created and used in Aodh
	// +kubebuilder:default=rabbitmq
	RabbitMqClusterName string `json:"rabbitMqClusterName,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:default=openstack
	// MariaDB instance name
	// Right now required by the maridb-operator to get the credentials from the instance to create the DB
	// Might not be required in future
	DatabaseInstance string `json:"databaseInstance"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=aodh
	// DatabaseAccount - optional MariaDBAccount CR name used for aodh DB, defaults to aodh
	DatabaseAccount string `json:"databaseAccount"`

	// PasswordSelectors - Selectors to identify the service from the Secret
	// +kubebuilder:default:={aodhService: AodhPassword}
	PasswordSelectors PasswordsSelector `json:"passwordSelector,omitempty"`

	// ServiceUser - optional username used for this service to register in keystone
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=aodh
	ServiceUser string `json:"serviceUser"`

	// Secret containing OpenStack password information
	// +kubebuilder:validation:Required
	// +kubebuilder:default=osp-secret
	Secret string `json:"secret"`

	// CustomServiceConfig - customize the service config using this parameter to change service defaults,
	// or overwrite rendered information using raw OpenStack config format. The content gets added to
	// to /etc/<service>/<service>.conf.d directory as custom.conf file.
	// +kubebuilder:default:="# add your customization here"
	CustomServiceConfig string `json:"customServiceConfig,omitempty"`

	// ConfigOverwrite - interface to overwrite default config files like e.g. logging.conf or policy.json.
	// But can also be used to add additional files. Those get added to the service config dir in /etc/<service> .
	// TODO: -> implement
	DefaultConfigOverwrite map[string]string `json:"defaultConfigOverwrite,omitempty"`

	// Override, provides the ability to override the generated manifest of several child resources.
	Override CKAPIOverrideSpec `json:"override,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// PreserveJobs - do not delete jobs after they finished e.g. to check logs
	PreserveJobs bool `json:"preserveJobs"`

	// Memcached instance name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=memcached
	MemcachedInstance string `json:"memcachedInstance"`

	// Host of user deployed prometheus
	// +kubebuilder:validation:Optional
	PrometheusHost string `json:"prometheusHost,omitempty"`

	// Port of user deployed prometheus
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	PrometheusPort int32 `json:"prometheusPort,omitempty"`

	// If defined, specifies which CA certificate to use for user deployed prometheus
	// +kubebuilder:validation:Optional
	// +nullable
	PrometheusTLSCaCertSecret *corev1.SecretKeySelector `json:"prometheusTLSCaCertSecret,omitempty"`

	// NetworkAttachmentDefinitions list of network attachment definitions the service pod gets attached to
	// +kubebuilder:validation:Optional
	NetworkAttachmentDefinitions []string `json:"networkAttachmentDefinitions,omitempty"`

	// +kubebuilder:validation:Optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	// TLS - Parameters related to the TLS
	TLS tls.API `json:"tls,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector to target subset of worker nodes running this service
	NodeSelector *map[string]string `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// TopologyRef to apply the Topology defined by the associated CR referenced
	// by name
	TopologyRef *topologyv1.TopoRef `json:"topologyRef,omitempty"`
}

// CKAPIOverrideSpec to override the generated manifest of several child resources.
type CKAPIOverrideSpec struct {
	// Override configuration for the Service created to serve traffic to the cluster.
	// The key must be the endpoint type (public, internal)
	Service map[service.Endpoint]service.RoutedOverrideSpec `json:"service,omitempty"`
}

// CloudKittyStatus defines the observed state of CloudKitty
type CloudKittyStatus struct {
	// ReadyCount of CloudKitty instances
	ReadyCount int32 `json:"readyCount,omitempty"`

	// Map of hashes to track e.g. job status
	Hash map[string]string `json:"hash,omitempty"`

	// Conditions
	Conditions condition.Conditions `json:"conditions,omitempty" optional:"true"`

	// Networks in addition to the cluster network, the service is attached to
	Networks []string `json:"networks,omitempty"`

	// TransportURLSecret - Secret containing RabbitMQ transportURL
	TransportURLSecret string `json:"transportURLSecret,omitempty"`

	// DatabaseHostname - Hostname for the database
	DatabaseHostname string `json:"databaseHostname,omitempty"`

	// PrometheusHost - Hostname for prometheus used for rating
	PrometheusHost string `json:"prometheusHostname,omitempty"`

	// PrometheusPort - Port for prometheus used for rating
	PrometheusPort int32 `json:"prometheusPort,omitempty"`

	// PrometheusTLS - Determines if TLS should be used for accessing prometheus
	PrometheusTLS bool `json:"prometheusTLS,omitempty"`

	// API endpoint
	APIEndpoints map[string]string `json:"apiEndpoint,omitempty"`

	// ObservedGeneration - the most recent generation observed for this
	// service. If the observed generation is less than the spec generation,
	// then the controller has not processed the latest changes injected by
	// the openstack-operator in the top-level CR (e.g. the ContainerImage)
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastAppliedTopology - the last applied Topology
	LastAppliedTopology *topologyv1.TopoRef `json:"lastAppliedTopology,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CloudKitty is the Schema for the cloudkitties API
type CloudKitty struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudKittySpec   `json:"spec,omitempty"`
	Status CloudKittyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CloudKittyList contains a list of CloudKitty
type CloudKittyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudKitty `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CloudKitty{}, &CloudKittyList{})
}

// RbacConditionsSet - set the conditions for the rbac object
func (instance CloudKitty) RbacConditionsSet(c *condition.Condition) {
	instance.Status.Conditions.Set(c)
}

// RbacNamespace - return the namespace
func (instance CloudKitty) RbacNamespace() string {
	return instance.Namespace
}

// RbacResourceName - return the name to be used for rbac objects (serviceaccount, role, rolebinding)
func (instance CloudKitty) RbacResourceName() string {
	return "telemetry-" + instance.Name
}

// SetupDefaultsCloudKitty - initializes any CRD field defaults based on environment variables (the defaulting mechanism itself is implemented via webhooks)
func SetupDefaultsCloudKitty() {
	// Acquire environmental defaults and initialize Telemetry defaults with them
	cloudKittyDefaults := CloudKittyDefaults{
		APIContainerImageURL:       util.GetEnvVar("RELATED_IMAGE_CLOUDKITTY_API_IMAGE_URL_DEFAULT", CloudKittyAPIContainerImage),
		ProcessorContainerImageURL: util.GetEnvVar("RELATED_IMAGE_CLOUDKITTY_PROCESSOR_IMAGE_URL_DEFAULT", CloudKittyProcessorContainerImage),
	}

	SetupCloudKittyDefaults(cloudKittyDefaults)
}

// GetSpecTopologyRef - Returns the LastAppliedTopology Set in the Status
func (instance *CloudKitty) GetSpecTopologyRef() *topologyv1.TopoRef {
	return instance.Spec.TopologyRef
}

// GetLastAppliedTopology - Returns the LastAppliedTopology Set in the Status
func (instance *CloudKitty) GetLastAppliedTopology() *topologyv1.TopoRef {
	return instance.Status.LastAppliedTopology
}

// SetLastAppliedTopology - Sets the LastAppliedTopology value in the Status
func (instance *CloudKitty) SetLastAppliedTopology(topologyRef *topologyv1.TopoRef) {
	instance.Status.LastAppliedTopology = topologyRef
}

// ValidateTopology -
func (instance *CloudKittySpecCore) ValidateTopology(
	basePath *field.Path,
	namespace string,
) field.ErrorList {
	var allErrs field.ErrorList
	allErrs = append(allErrs, topologyv1.ValidateTopologyRef(
		instance.TopologyRef,
		*basePath.Child("topologyRef"), namespace)...)
	return allErrs
}
