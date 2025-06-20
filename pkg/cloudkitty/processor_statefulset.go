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

package cloudkitty

import (
	"fmt"

	"github.com/openstack-k8s-operators/lib-common/modules/common/annotations"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	memcachedv1 "github.com/openstack-k8s-operators/infra-operator/apis/memcached/v1beta1"
	topologyv1 "github.com/openstack-k8s-operators/infra-operator/apis/topology/v1beta1"
	telemetryv1 "github.com/openstack-k8s-operators/telemetry-operator/api/v1beta1"
)

const (
	// ProcServiceCommand -
	ProcServiceCommand = "/usr/local/bin/kolla_set_configs && /usr/local/bin/kolla_start"
)

// ProcStatefulSet func
func ProcStatefulSet(
	instance *telemetryv1.CloudKitty,
	configHash string,
	labels map[string]string,
	topology *topologyv1.Topology,
	memcached *memcachedv1.Memcached,
) (*appsv1.StatefulSet, error) {
	runAsUser := int64(0)

	args := []string{"-c"}
	args = append(args, ProcServiceCommand)

	/*
		processorLivenessProbe := &corev1.Probe{
			TimeoutSeconds:      5,
			PeriodSeconds:       5,
			InitialDelaySeconds: 300,
		}
		processorLivenessProbe.Exec = &corev1.ExecAction{
			Command: []string{"/usr/bin/python3", ProcessorHCScript},
		}
	*/

	// create Volume and VolumeMounts
	volumes := getProcVolumes()
	volumeMounts := getVolumeMounts("cloudkitty-proc")

	// add openstack CA cert if defined
	if instance.Spec.TLS.CaBundleSecretName != "" {
		volumes = append(volumes, instance.Spec.TLS.CreateVolume())
		volumeMounts = append(volumeMounts, instance.Spec.TLS.CreateVolumeMounts(nil)...)
	}

	// add prometheus CA cert if defined
	if instance.Spec.PrometheusTLSCaCertSecret != nil {
		volumes = append(volumes, getCustomPrometheusCaVolume(instance.Spec.PrometheusTLSCaCertSecret.LocalObjectReference.Name))
		volumeMounts = append(volumeMounts, getCustomPrometheusCaVolumeMount(instance.Spec.PrometheusTLSCaCertSecret.Key))
	}

	// add MTLS cert if defined
	if memcached.GetMemcachedMTLSSecret() != "" {
		volumes = append(volumes, memcached.CreateMTLSVolume())
		volumeMounts = append(volumeMounts, memcached.CreateMTLSVolumeMounts(nil, nil)...)
	}

	envVarsAodh := map[string]env.Setter{}
	envVarsAodh["KOLLA_CONFIG_STRATEGY"] = env.SetValue("COPY_ALWAYS")
	envVarsAodh["CONFIG_HASH"] = env.SetValue(configHash)

	var replicas int32 = 1

	apiContainer := corev1.Container{
		ImagePullPolicy: corev1.PullAlways,
		Command: []string{
			"/bin/bash",
		},
		Args:  args,
		Image: instance.Spec.ProcessorImage,
		Name:  "cloudkitty-proc",
		Env:   env.MergeEnvs([]corev1.EnvVar{}, envVarsAodh),
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: &runAsUser,
		},
		VolumeMounts: volumeMounts,
	}

	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: instance.Namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: instance.RbacResourceName(),
			Containers: []corev1.Container{
				apiContainer,
			},
		},
	}

	if instance.Spec.NodeSelector != nil {
		pod.Spec.NodeSelector = *instance.Spec.NodeSelector
	}
	if topology != nil {
		topology.ApplyTo(&pod)
	}

	statefulset := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: instance.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			PodManagementPolicy: appsv1.ParallelPodManagement,
			Replicas:            &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: pod,
		},
	}

	statefulset.Spec.Template.Spec.Volumes = volumes

	// networks to attach to
	nwAnnotation, err := annotations.GetNADAnnotation(instance.Namespace, instance.Spec.NetworkAttachmentDefinitions)
	if err != nil {
		return nil, fmt.Errorf("failed create network annotation from %s: %w",
			instance.Spec.NetworkAttachmentDefinitions, err)
	}
	statefulset.Spec.Template.Annotations = util.MergeStringMaps(statefulset.Spec.Template.Annotations, nwAnnotation)

	return statefulset, nil
}
