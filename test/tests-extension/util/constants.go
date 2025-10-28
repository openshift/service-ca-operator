package util

// Constants copied from github.com/openshift/service-ca-operator/pkg/controller/api
// to avoid dependency issues in container builds

const (
	// InjectionDataKey is the key used to identify the CA bundle in the injection
	InjectionDataKey = "service-ca.crt"
	
	// SigningCABundleConfigMapName is the name of the signing CA bundle configmap
	SigningCABundleConfigMapName = "signing-cabundle"
	
	// BundleDataKey is the key used to identify the CA bundle in the signing secret
	BundleDataKey = "ca-bundle.crt"
	
	// InjectCABundleAnnotationName is the annotation name for CA bundle injection
	InjectCABundleAnnotationName = "service.beta.openshift.io/inject-cabundle"
	
	// ServingCertSecretAnnotation stores the name of the secret to generate into
	ServingCertSecretAnnotation = "service.beta.openshift.io/serving-cert-secret-name"
)