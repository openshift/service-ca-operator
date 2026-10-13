package api

// Common controller/operator resource names
const (
	// Config instance
	OperatorConfigInstanceName = "cluster"

	// ConfigMaps
	SigningCABundleConfigMapName = "signing-cabundle"

	// SAs
	ServiceCASAName = "service-ca"

	// Deployments
	ServiceCADeploymentName = "service-ca"

	// Secrets
	ServiceCASecretName = "signing-key"
)
