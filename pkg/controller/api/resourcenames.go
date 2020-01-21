package api

import (
	"k8s.io/apimachinery/pkg/util/sets"
)

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

// Names of deployments for running service ca controllers independently. Intended
// to support the operator identifying old resources to be removed after upgrade and
// allowing the unified controller to detect when a downgrade has occurred.
var IndependentDeploymentNames = sets.NewString(
	"apiservice-cabundle-injector",
	"configmap-cabundle-injector",
	"service-serving-cert-signer",
)
