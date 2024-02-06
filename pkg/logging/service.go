/*
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

package logging

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	ctrl "sigs.k8s.io/controller-runtime"

	helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	service "github.com/openstack-k8s-operators/lib-common/modules/common/service"
	util "github.com/openstack-k8s-operators/lib-common/modules/common/util"
	condition "github.com/openstack-k8s-operators/lib-common/modules/common/condition"

	telemetryv1 "github.com/openstack-k8s-operators/telemetry-operator/api/v1beta1"
)

// Service creates a LoadBalancer service for openshift-logging
func Service(
	instance *telemetryv1.Logging,
	helper *helper.Helper,
	labels map[string]string,
) (reconcile.Result, error) {

	svcOverride := instance.Spec.Override.Service
	if svcOverride == nil {
		svcOverride = &service.RoutedOverrideSpec{}
	}
	if svcOverride.EmbeddedLabelsAnnotations == nil {
		svcOverride.EmbeddedLabelsAnnotations = &service.EmbeddedLabelsAnnotations{}
	}

	endpointTypeStr := "internal"

	exportLabels := util.MergeStringMaps(
		labels,
		map[string]string{
			service.AnnotationEndpointKey: endpointTypeStr,
		},
	)

	selector := map[string]string{
		"app.kubernetes.io/instance": "collector",
		"component":                  "collector",
		"provider":                   "openshift",
	}

	// Create the service
	svc, err := service.NewService(
		service.GenericService(&service.GenericServiceDetails{
			Name:      "openstack-" + ServiceName,
			Namespace: instance.Namespace,
			Labels:    exportLabels,
			Selector:  selector,
			Port: service.GenericServicePort{
				Name:     	"syslog",
				Protocol:   corev1.Protocol("TCP"),
				Port:       instance.Spec.Port,
			},
		}),
		5,
		&svcOverride.OverrideSpec,
	)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ExposeServiceReadyErrorMessage,
			err.Error()))

		return ctrl.Result{}, err
	}

	svc.AddAnnotation(map[string]string{
		service.AnnotationEndpointKey: endpointTypeStr,
	})
	svc.AddAnnotation(map[string]string{
		service.AnnotationIngressCreateKey: "false",
	})
	if svc.GetServiceType() == corev1.ServiceTypeLoadBalancer {
		svc.AddAnnotation(map[string]string{
			service.AnnotationHostnameKey: svc.GetServiceHostname(), // add annotation to register service name in dnsmasq
		})
	}

	ctrlResult, err := svc.CreateOrPatch(context.TODO(), helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.ExposeServiceReadyErrorMessage,
			err.Error()))

		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.ExposeServiceReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.ExposeServiceReadyRunningMessage))
		return ctrlResult, nil
	}
}

// Service creates a LoadBalancer service for openshift-logging
/*func Service(
	instance *telemetryv1.Logging,
	helper *helper.Helper,
	labels map[string]string,
) (*corev1.Service, controllerutil.OperationResult, error) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openstack-" + ServiceName,
			Namespace: instance.Spec.CLONamespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(context.TODO(), helper.GetClient(), service, func() error {
		//service.Labels = labels
		service.Spec.Ports = []corev1.ServicePort{{
			Protocol:   corev1.Protocol("TCP"),
			Port:       instance.Spec.Port,
			TargetPort: intstr.FromInt(instance.Spec.TargetPort),
		}}
		service.Spec.Selector = map[string]string{
			"app.kubernetes.io/instance": "collector",
			"component":                  "collector",
			"provider":                   "openshift",
		}
		service.Annotations = instance.Spec.Annotations
		service.Spec.Type = "LoadBalancer"

		return nil
	})

	return service, op, err
}*/
