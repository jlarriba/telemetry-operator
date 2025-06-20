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

package cloudkitty

const (
	// APIServiceName -
	ServiceName = "cloudkitty"

	// APIServiceName -
	APIServiceName = "cloudkitty-api"

	// ProcServiceName
	ProcServiceName = "cloudkitty-proc"

	// ServiceType -
	ServiceType = "CloudKitty"

	// DatabaseName - Name of the database used in CREATE DATABASE statement
	DatabaseName = "cloudkitty"

	// DatabaseCRName - Name of the MariaDBDatabase CR
	DatabaseCRName = "cloudkitty"

	// DatabaseUsernamePrefix - used by EnsureMariaDBAccount when a new username
	// is to be generated, e.g. "cloudkitty_e5a4", "cloudkitty_78bc", etc
	DatabaseUsernamePrefix = "cloudkitty"

	// CloudKittyAPIPort -
	CloudKittyAPIPort = 8889

	// CustomPrometheusCaCertFolderPath -
	CustomPrometheusCaCertFolderPath = "/etc/pki/ca-trust/extracted/pem/"

	PrometheusEndpointSecret = "metric-storage-prometheus-endpoint"
)
