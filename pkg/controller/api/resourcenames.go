package api

// Common controller/operator resource names
const (
	// Config instance
	OperatorConfigInstanceName = "cluster"

	// ConfigMaps
	SignerControllerConfigMapName             = "service-serving-cert-signer-config"
	APIServiceInjectorConfigMapName           = "apiservice-cabundle-injector-config"
	ConfigMapInjectorConfigMapName            = "configmap-cabundle-injector-config"
	SigningCABundleConfigMapName              = "signing-cabundle"
	WebhookConfigurationInjectorConfigMapName = "webhookconfiguration-cabundle-injector-config"

	// SAs
	SignerControllerSAName             = "service-serving-cert-signer-sa"
	APIServiceInjectorSAName           = "apiservice-cabundle-injector-sa"
	ConfigMapInjectorSAName            = "configmap-cabundle-injector-sa"
	WebhookConfigurationInjectorSAName = "webhookconfiguration-cabundle-injector-sa"

	// Services
	SignerControllerServiceName = "service-serving-cert-signer"

	// Deployments
	SignerControllerDeploymentName             = "service-serving-cert-signer"
	APIServiceInjectorDeploymentName           = "apiservice-cabundle-injector"
	ConfigMapInjectorDeploymentName            = "configmap-cabundle-injector"
	WebhookConfigurationInjectorDeploymentName = "webhookconfiguration-cabundle-injector"

	// Secrets
	SignerControllerSecretName = "signing-key"
)
