package api

// Common controller/operator resource names
const (
	// Config instance
	OperatorConfigInstanceName = "cluster"

	// ConfigMaps
	SigningCABundleConfigMapName = "signing-cabundle"

	// SAs
	SignerControllerSAName   = "service-serving-cert-signer-sa"
	APIServiceInjectorSAName = "apiservice-cabundle-injector-sa"
	ConfigMapInjectorSAName  = "configmap-cabundle-injector-sa"

	// Services
	SignerControllerServiceName = "service-serving-cert-signer"

	// Deployments
	SignerControllerDeploymentName   = "service-serving-cert-signer"
	APIServiceInjectorDeploymentName = "apiservice-cabundle-injector"
	ConfigMapInjectorDeploymentName  = "configmap-cabundle-injector"

	// Secrets
	SignerControllerSecretName = "signing-key"
)
