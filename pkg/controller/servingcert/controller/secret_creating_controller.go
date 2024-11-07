package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	informers "k8s.io/client-go/informers/core/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	apiannotations "github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/cryptoextensions"
)

type serviceServingCertController struct {
	serviceClient kcoreclient.ServicesGetter
	secretClient  kcoreclient.SecretsGetter

	serviceLister listers.ServiceLister
	secretLister  listers.SecretLister

	ca                 *crypto.CA
	intermediateCACert *x509.Certificate
	dnsSuffix          string
	maxRetries         int

	certificateLifetime time.Duration
}

func NewServiceServingCertController(
	services informers.ServiceInformer,
	secrets informers.SecretInformer,
	serviceClient kcoreclient.ServicesGetter,
	secretClient kcoreclient.SecretsGetter,
	ca *crypto.CA,
	intermediateCACert *x509.Certificate,
	dnsSuffix string,
	recorder events.Recorder,
	certificateLifetime time.Duration,
) factory.Controller {

	sc := &serviceServingCertController{
		serviceClient: serviceClient,
		secretClient:  secretClient,

		serviceLister: services.Lister(),
		secretLister:  secrets.Lister(),

		ca:                  ca,
		intermediateCACert:  intermediateCACert,
		dnsSuffix:           dnsSuffix,
		maxRetries:          10,
		certificateLifetime: certificateLifetime,
	}

	return factory.New().
		WithInformersQueueKeyFunc(namespacedObjToQueueKey, services.Informer()).
		WithFilteredEventsInformersQueueKeyFunc(serviceFromSecretQueueFunc, secretsQueueFilter, secrets.Informer()).
		WithSync(sc.Sync).
		ToController("ServiceServingCertController", recorder.WithComponentSuffix("service-serving-cert-controller"))
}

func namespacedObjToQueueKey(obj runtime.Object) string {
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), metaObj.GetName())
}

func serviceNameFromSecretEventObj(obj interface{}) (string, bool) {
	secret, secretOK := obj.(*corev1.Secret)
	if !secretOK {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return "", false
		}

		secret, secretOK = tombstone.Obj.(*corev1.Secret)
		if !secretOK {
			return "", false
		}
	}
	return toServiceName(secret)
}

func serviceFromSecretQueueFunc(obj runtime.Object) string {
	svcName, _ := serviceNameFromSecretEventObj(obj)
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), svcName)
}

func secretsQueueFilter(obj interface{}) bool {
	_, ok := serviceNameFromSecretEventObj(obj)
	return ok
}

func objFromQueueKey(qKey string) (string, string) {
	nsName := strings.SplitN(qKey, "/", 2)
	return nsName[0], nsName[1]
}

func (sc *serviceServingCertController) Sync(ctx context.Context, syncContext factory.SyncContext) error {
	serviceNS, serviceName := objFromQueueKey(syncContext.QueueKey())

	sharedService, err := sc.serviceLister.Services(serviceNS).Get(serviceName)
	if kapierrors.IsNotFound(err) {
		klog.V(4).Infof("service %s/%s not found", serviceNS, serviceName)
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to get service %s/%s: %v", serviceNS, serviceName, err)
	}

	if !sc.requiresCertGeneration(sharedService) {
		return nil
	}

	// make a copy to avoid mutating cache state
	serviceCopy := sharedService.DeepCopy()
	return sc.generateCert(ctx, serviceCopy)
}

func (sc *serviceServingCertController) generateCert(ctx context.Context, serviceCopy *corev1.Service) error {
	klog.V(4).Infof("generating new cert for %s/%s", serviceCopy.GetNamespace(), serviceCopy.GetName())
	if serviceCopy.Annotations == nil {
		serviceCopy.Annotations = map[string]string{}
	}

	secret := toBaseSecret(serviceCopy)
	if err := toRequiredSecret(sc.dnsSuffix, sc.ca, sc.intermediateCACert, serviceCopy, secret, sc.certificateLifetime); err != nil {
		return err
	}
	setSecretOwnerDescription(secret, serviceCopy)

	_, err := sc.secretClient.Secrets(serviceCopy.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !kapierrors.IsAlreadyExists(err) {
		return sc.updateServiceFailure(ctx, serviceCopy, err)
	}
	if kapierrors.IsAlreadyExists(err) {
		actualSecret, err := sc.secretClient.Secrets(serviceCopy.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return sc.updateServiceFailure(ctx, serviceCopy, err)
		}

		if !uidsEqual(actualSecret, serviceCopy) {
			uidErr := fmt.Errorf("secret %s/%s does not have corresponding service UID %v", actualSecret.GetNamespace(), actualSecret.GetName(), serviceCopy.UID)
			return sc.updateServiceFailure(ctx, serviceCopy, uidErr)
		}
		klog.V(4).Infof("renewing cert in existing secret %s/%s", secret.GetNamespace(), secret.GetName())
		// Actually update the secret in the regeneration case (the secret already exists but we want to update to a new cert).
		_, updateErr := sc.secretClient.Secrets(secret.GetNamespace()).Update(ctx, secret, metav1.UpdateOptions{})
		if updateErr != nil {
			return sc.updateServiceFailure(ctx, serviceCopy, updateErr)
		}
	}

	sc.resetServiceAnnotations(serviceCopy)
	_, err = sc.serviceClient.Services(serviceCopy.Namespace).Update(ctx, serviceCopy, metav1.UpdateOptions{})

	return err
}

func getNumFailures(service *corev1.Service) int {
	numFailuresString := service.Annotations[api.ServingCertErrorNumAnnotation]
	if len(numFailuresString) == 0 {
		numFailuresString = service.Annotations[api.AlphaServingCertErrorNumAnnotation]
		if len(numFailuresString) == 0 {
			return 0
		}
	}

	numFailures, err := strconv.Atoi(numFailuresString)
	if err != nil {
		return 0
	}

	return numFailures
}

func (sc *serviceServingCertController) requiresCertGeneration(service *corev1.Service) bool {
	// check the secret since it could not have been created yet
	secretName := service.Annotations[api.ServingCertSecretAnnotation]
	if len(secretName) == 0 {
		secretName = service.Annotations[api.AlphaServingCertSecretAnnotation]
		if len(secretName) == 0 {
			return false
		}
	}

	secret, err := sc.secretLister.Secrets(service.Namespace).Get(secretName)
	if kapierrors.IsNotFound(err) {
		// we have not created the secret yet
		return true
	}
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get the secret %s/%s: %v", service.Namespace, secretName, err))
		return false
	}

	if !sc.secretRequiresCertGeneration(service, secret) {
		return false
	}

	// we have failed too many times on this service, give up
	if getNumFailures(service) >= sc.maxRetries {
		return false
	}

	// the secret exists but the service was either not updated to include the correct created
	// by annotation or it does not match what we expect (i.e. the certificate has been rotated)
	return true
}

// Returns false if pre-existing secret is appropriate for service and the current CA,
// true if not, or if there was a parsing error (i.e. we regenerate on invalid secret)
func (sc *serviceServingCertController) secretRequiresCertGeneration(service *corev1.Service, secret *corev1.Secret) bool {
	certs, err := cert.ParseCertsPEM(secret.Data[corev1.TLSCertKey])
	if err != nil {
		klog.V(4).Infof("warning: error parsing certificate data in %s/%s during regeneration check: %v",
			secret.Namespace, secret.Name, err)
		return true
	}
	if len(certs) == 0 || certs[0] == nil {
		klog.V(4).Infof("warning: no certs returned from ParseCertsPEM during regeneration check")
		return true
	}
	cert := certs[0]

	if !sc.issuedByCurrentCA(cert) {
		return true
	}
	if !sc.certContainsExpectedSubjects(service, cert) {
		return true
	}
	return false
}

// Returns true if the certificate was issued by the current CA, false if not.
//
// Determination of issuance will default to comparison of the certificate's
// AuthorityKeyID and the CA's SubjectKeyId, and fall back to comparison of the
// certificate's Issuer.CommonName and the CA's Subject.CommonName (in case the CA was
// generated prior to the addition of key identifiers).
func (sc *serviceServingCertController) issuedByCurrentCA(cert *x509.Certificate) bool {
	certAuthorityKeyId := cert.AuthorityKeyId
	caSubjectKeyId := sc.ca.Config.Certs[0].SubjectKeyId
	// Use key identifier chaining if the SubjectKeyId is populated in the CA
	// certificate. AuthorityKeyId may not be set in the serving certificate if it was
	// generated before serving cert generation was updated to include the field.
	if len(caSubjectKeyId) > 0 {
		return bytes.Equal(certAuthorityKeyId, caSubjectKeyId)
	}

	// Fall back to name-based chaining for a legacy service CA that was generated
	// without SubjectKeyId or AuthorityKeyId.
	return cert.Issuer.CommonName == sc.commonName()
}

func (sc *serviceServingCertController) commonName() string {
	return sc.ca.Config.Certs[0].Subject.CommonName
}

// Returns true if the certificate contains all subjects expected for service, false if not.
//
// This can happen if an earlier version generated a certificate for a headless service
// without including the wildcard subjects matching the individual pods.
func (sc *serviceServingCertController) certContainsExpectedSubjects(service *corev1.Service, cert *x509.Certificate) bool {
	// We only compare cert.DNSNames, and ignore other possible certificate subjects that this code
	// never generates.
	expectedSubjects := certSubjectsForService(service, sc.dnsSuffix)
	certSubjects := sets.NewString(cert.DNSNames...)
	return certSubjects.Equal(expectedSubjects)
}

// updateServiceFailure updates the service's error annotations with err.
// Returns the passed in err normally, or nil if the amount of failures has hit the max. This is so it can act as a
// return to the sync method.
func (sc *serviceServingCertController) updateServiceFailure(ctx context.Context, service *corev1.Service, err error) error {
	setErrAnnotation(service, err)
	incrementFailureNumAnnotation(service)
	_, updateErr := sc.serviceClient.Services(service.Namespace).Update(ctx, service, metav1.UpdateOptions{})
	if updateErr != nil {
		klog.V(4).Infof("warning: failed to update failure annotations on service %s: %v", service.Name, updateErr)
	}
	// Past the max retries means we've handled this failure enough, so forget it from the queue.
	if updateErr == nil && getNumFailures(service) >= sc.maxRetries {
		return nil
	}

	// Return the original error.
	return err
}

// Sets the service CA common name and clears any errors.
func (sc *serviceServingCertController) resetServiceAnnotations(service *corev1.Service) {
	service.Annotations[api.AlphaServingCertCreatedByAnnotation] = sc.commonName()
	service.Annotations[api.ServingCertCreatedByAnnotation] = sc.commonName()
	delete(service.Annotations, api.AlphaServingCertErrorAnnotation)
	delete(service.Annotations, api.AlphaServingCertErrorNumAnnotation)
	delete(service.Annotations, api.ServingCertErrorAnnotation)
	delete(service.Annotations, api.ServingCertErrorNumAnnotation)
}

func ownerRef(service *corev1.Service) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Service",
		Name:       service.Name,
		UID:        service.UID,
	}
}

func toBaseSecret(service *corev1.Service) *corev1.Secret {
	// Use beta annotations
	if _, ok := service.Annotations[api.ServingCertSecretAnnotation]; ok {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      service.Annotations[api.ServingCertSecretAnnotation],
				Namespace: service.Namespace,
				Annotations: map[string]string{
					api.ServiceUIDAnnotation:  string(service.UID),
					api.ServiceNameAnnotation: service.Name,
				},
			},
			Type: corev1.SecretTypeTLS,
		}
	}
	// Use alpha annotations
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.Annotations[api.AlphaServingCertSecretAnnotation],
			Namespace: service.Namespace,
			Annotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  string(service.UID),
				api.AlphaServiceNameAnnotation: service.Name,
			},
		},
		Type: corev1.SecretTypeTLS,
	}
}

func certSubjectsForService(service *corev1.Service, dnsSuffix string) sets.String {
	res := sets.NewString()
	serviceHostname := service.Name + "." + service.Namespace + ".svc"
	res.Insert(
		serviceHostname,
		serviceHostname+"."+dnsSuffix,
	)
	if service.Spec.ClusterIP == corev1.ClusterIPNone {
		podWildcard := "*." + service.Name + "." + service.Namespace + ".svc"
		res.Insert(
			podWildcard,
			podWildcard+"."+dnsSuffix,
		)
	}
	return res
}

func MakeServingCert(dnsSuffix string, ca *crypto.CA, intermediateCACert *x509.Certificate, service *corev1.Service, lifetime time.Duration) (*crypto.TLSCertificateConfig, error) {
	subjects := certSubjectsForService(service, dnsSuffix)
	servingCert, err := ca.MakeServerCert(
		subjects,
		lifetime,
		cryptoextensions.ServiceServerCertificateExtensionV1(service.UID),
	)
	if err != nil {
		return nil, err
	}

	// Including the intermediate cert will ensure that clients with a
	// stale ca bundle (containing the previous CA but not the current
	// one) will be able to trust the serving cert.
	if intermediateCACert != nil {
		servingCert.Certs = append(servingCert.Certs, intermediateCACert)
	}

	return servingCert, nil
}

func toRequiredSecret(dnsSuffix string, ca *crypto.CA, intermediateCACert *x509.Certificate, service *corev1.Service, secretCopy *corev1.Secret, lifetime time.Duration) error {
	servingCert, err := MakeServingCert(dnsSuffix, ca, intermediateCACert, service, lifetime)
	if err != nil {
		return err
	}
	certBytes, keyBytes, err := servingCert.GetPEMBytes()
	if err != nil {
		return err
	}
	if secretCopy.Annotations == nil {
		secretCopy.Annotations = map[string]string{}
	}
	// let garbage collector cleanup map allocation, for simplicity
	secretCopy.Data = map[string][]byte{
		corev1.TLSCertKey:       certBytes,
		corev1.TLSPrivateKeyKey: keyBytes,
	}

	secretCopy.Annotations[api.AlphaServingCertExpiryAnnotation] = servingCert.Certs[0].NotAfter.Format(time.RFC3339)
	secretCopy.Annotations[api.ServingCertExpiryAnnotation] = servingCert.Certs[0].NotAfter.Format(time.RFC3339)

	controller.EnsureOwnerRef(secretCopy, ownerRef(service))

	return nil
}

func setErrAnnotation(service *corev1.Service, err error) {
	service.Annotations[api.ServingCertErrorAnnotation] = err.Error()
	service.Annotations[api.AlphaServingCertErrorAnnotation] = err.Error()
}

func incrementFailureNumAnnotation(service *corev1.Service) {
	numFailure := strconv.Itoa(getNumFailures(service) + 1)
	service.Annotations[api.ServingCertErrorNumAnnotation] = numFailure
	service.Annotations[api.AlphaServingCertErrorNumAnnotation] = numFailure
}

func uidsEqual(secret *corev1.Secret, service *corev1.Service) bool {
	suid := string(service.UID)
	return secret.Annotations[api.AlphaServiceUIDAnnotation] == suid ||
		secret.Annotations[api.ServiceUIDAnnotation] == suid
}

// Set ownership and description annotations. Return true if there are changes on
// the two annotations
func setSecretOwnerDescription(secret *corev1.Secret, service *corev1.Service) bool {
	changed := false
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
		changed = true
	}
	// Set service CA owner annotation to generated secret
	if len(secret.Annotations[apiannotations.OpenShiftComponent]) == 0 {
		secret.Annotations[apiannotations.OpenShiftComponent] = api.OwningJiraComponent
		changed = true
	}
	// Generate a description for generated secret if not existed already
	if len(secret.Annotations[apiannotations.OpenShiftDescription]) == 0 {
		secret.Annotations[apiannotations.OpenShiftDescription] = fmt.Sprintf("Secret contains a pair signed serving certificate/key that is generated by Service CA operator for service/%s with hostname %s.%s.svc and is annotated to the service with annotating a service resource with 'service.beta.openshift.io/serving-cert-secret-name: %s'. The certificate is valid for 2 years.", service.Name, service.Name, service.Namespace, secret.Name)
		changed = true
	}
	return changed
}
