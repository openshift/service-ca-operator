package api

// Constants for Service CA
const (
	// ForcedRotationReasonAnnotationName is the name of an annotation indicating
	// the most recent reason that a service CA rotation was forced. The annotation
	// will be set on the signing secret after the successful completion of a forced
	// rotation.
	ForcedRotationReasonAnnotationName = "service-ca.operators.openshift.io/forced-rotation-reason"
	// BundleDataKey is the key used to identify the CA bundle in the signing
	// secret.
	BundleDataKey = "ca-bundle.crt"
	// IntermediateDataKey is the key used to identify the post-rotation
	// trust-bridging certificate in the signing secret.
	IntermediateDataKey = "intermediate-ca.crt"
)

// Constants for CA bundle injection
const (
	InjectCABundleAnnotationName      = "service.beta.openshift.io/inject-cabundle"
	AlphaInjectCABundleAnnotationName = "service.alpha.openshift.io/inject-cabundle"
	InjectionDataKey                  = "service-ca.crt"
)

// Annotations on service
const (
	// TODO(marun) When adding a GA serving cert annotation, consider
	// discontinuing the practice of including the issuing cert with the serving
	// cert. This behavior was accidental (at some point the issuing CA was an
	// intermediate rather than the current self-signed root) but had to be
	// maintained to support legacy clients that ended up reusing the serving cert
	// as a CA bundle. Clients of a GA annotation should be expected to use a
	// proper CA bundle.

	// ServingCertSecretAnnotation stores the name of the secret to generate into.
	ServingCertSecretAnnotation      = "service.beta.openshift.io/serving-cert-secret-name"
	AlphaServingCertSecretAnnotation = "service.alpha.openshift.io/serving-cert-secret-name"
	// ServingCertCreatedByAnnotation stores the of the signer common name.  This could be used later to see if the
	// services need to have the the serving certs regenerated.  The presence and matching of this annotation prevents
	// regeneration
	ServingCertCreatedByAnnotation      = "service.beta.openshift.io/serving-cert-signed-by"
	AlphaServingCertCreatedByAnnotation = "service.alpha.openshift.io/serving-cert-signed-by"
	// ServingCertErrorAnnotation stores the error that caused cert generation failures.
	ServingCertErrorAnnotation      = "service.beta.openshift.io/serving-cert-generation-error"
	AlphaServingCertErrorAnnotation = "service.alpha.openshift.io/serving-cert-generation-error"
	// ServingCertErrorNumAnnotation stores how many consecutive errors we've hit.  A value of the maxRetries will prevent
	// the controller from reattempting until it is cleared.
	ServingCertErrorNumAnnotation      = "service.beta.openshift.io/serving-cert-generation-error-num"
	AlphaServingCertErrorNumAnnotation = "service.alpha.openshift.io/serving-cert-generation-error-num"
)

// Annotations on StatefulSet:
// - AlphaServingCertSecretAnnotation
// - AlphaServingCertCreatedByAnnotation
// - AlphaServingCertErrorAnnotation
// - AlphaServingCertErrorNumAnnotation
// all use the semantics documented for service annotations above. The .beta. annotations are
// not used on StatefulSets.

// Annotations on secret
const (
	// ServiceUIDAnnotation is an annotation on a secret that indicates which service created it, by UID
	ServiceUIDAnnotation      = "service.beta.openshift.io/originating-service-uid"
	AlphaServiceUIDAnnotation = "service.alpha.openshift.io/originating-service-uid"
	// ServiceNameAnnotation is an annotation on a secret that indicates which service created it, by Name to allow reverse lookups on services
	// for comparison against UIDs
	ServiceNameAnnotation      = "service.beta.openshift.io/originating-service-name"
	AlphaServiceNameAnnotation = "service.alpha.openshift.io/originating-service-name"

	// AlphaStatefulSetUIDAnnotation is an annotation on a secret that indicates which StatefulSet created it, by UID
	AlphaStatefulSetUIDAnnotation = "service.alpha.openshift.io/originating-StatefulSet-uid"
	// AlphaStatefulSetNameAnnotation is an annotation on a secret that indicates which Statefulset created it, by Name to allow reverse lookups on StatefulSets
	// for comparison against UIDs
	AlphaStatefulSetNameAnnotation = "service.alpha.openshift.io/originating-StatefulSet-name"

	// ServingCertExpiryAnnotation is an annotation that holds the expiry time of the certificate.  It accepts time in the
	// RFC3339 format: 2018-11-29T17:44:39Z .
	// On a StatefulSet secret, this records the earliest expiry time from all certificates contained in the secret.
	ServingCertExpiryAnnotation      = "service.beta.openshift.io/expiry"
	AlphaServingCertExpiryAnnotation = "service.alpha.openshift.io/expiry"
)
