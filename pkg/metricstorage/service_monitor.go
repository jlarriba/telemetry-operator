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

package metricstorage

import (
	"fmt"

	tls "github.com/openstack-k8s-operators/lib-common/modules/common/tls"
	telemetryv1 "github.com/openstack-k8s-operators/telemetry-operator/api/v1beta1"
	monv1 "github.com/rhobs/obo-prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceMonitor creates a ServiceMonitor CR
func ServiceMonitor(
	instance *telemetryv1.MetricStorage,
	labels map[string]string,
	selector map[string]string,
	serverName string,
	port string,
) *monv1.ServiceMonitor {
	var scrapeInterval monv1.Duration
	if instance.Spec.MonitoringStack != nil && instance.Spec.MonitoringStack.ScrapeInterval != "" {
		scrapeInterval = monv1.Duration(instance.Spec.MonitoringStack.ScrapeInterval)
	} else if instance.Spec.CustomMonitoringStack != nil && *instance.Spec.CustomMonitoringStack.PrometheusConfig.ScrapeInterval != monv1.Duration("") {
		scrapeInterval = *instance.Spec.CustomMonitoringStack.PrometheusConfig.ScrapeInterval
	} else {
		scrapeInterval = telemetryv1.DefaultScrapeInterval
	}

	serviceMonitor := &monv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", instance.Name, serverName),
			Namespace: instance.Namespace,
			Labels:    labels,
		},
		Spec: monv1.ServiceMonitorSpec{
			Endpoints: []monv1.Endpoint{
				{
					Interval: scrapeInterval,
					MetricRelabelConfigs: []*monv1.RelabelConfig{
						{
							Action:       "labeldrop",
							Regex:        "pod",
							SourceLabels: []monv1.LabelName{},
						},
						{
							Action:       "labeldrop",
							Regex:        "namespace",
							SourceLabels: []monv1.LabelName{},
						},
						{
							Action:       "labeldrop",
							Regex:        "instance",
							SourceLabels: []monv1.LabelName{},
						},
						{
							Action:       "labeldrop",
							Regex:        "job",
							SourceLabels: []monv1.LabelName{},
						},
						{
							Action:       "labeldrop",
							Regex:        "publisher",
							SourceLabels: []monv1.LabelName{},
						},
					},
				},
			},
			Selector: metav1.LabelSelector{
				MatchLabels: selector,
			},
		},
	}
	if port != "" {
		serviceMonitor.Spec.Endpoints[0].Port = port
	}
	if instance.Spec.PrometheusTLS.Enabled() {
		serviceMonitor.Spec.Endpoints[0].Scheme = "https"
		serviceMonitor.Spec.Endpoints[0].TLSConfig = &monv1.TLSConfig{
			CAFile: fmt.Sprintf("/etc/prometheus/secrets/%s/%s", instance.Spec.PrometheusTLS.CaBundleSecretName, tls.CABundleKey),
			SafeTLSConfig: monv1.SafeTLSConfig{
				ServerName: serverName,
			},
		}
	}
	return serviceMonitor
}
