package controller

import (
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	informers "k8s.io/client-go/informers/core/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type serviceServingCertController struct {
	serviceClient kcoreclient.ServicesGetter
	secretClient  kcoreclient.SecretsGetter

	serviceLister listers.ServiceLister
	secretLister  listers.SecretLister

	servingCA  *ServingCA
	maxRetries int
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
) factory.Controller {
	sc := &serviceServingCertController{
		serviceClient: serviceClient,
		secretClient:  secretClient,

		serviceLister: services.Lister(),
		secretLister:  secrets.Lister(),

		servingCA:  NewServingCA(ca, intermediateCACert, dnsSuffix),
		maxRetries: 10,
	}

	return factory.New().
		WithInformersQueueKeyFunc(namespacedObjToQueueKey, services.Informer()).
		WithFilteredEventsInformersQueueKeyFunc(serviceFromSecretQueueFunc, secretsServiceNameQueueFilter, secrets.Informer()).
		WithSync(sc.Sync).
		ToController("ServiceServingCertController", recorder.WithComponentSuffix("service-serving-cert-controller"))
}

func serviceNameFromSecretEventObj(obj interface{}) (string, bool) {
	secret := secretFromSecretEventObj(obj)
	if secret == nil {
		return "", false
	}
	return toServiceName(secret)
}

func serviceFromSecretQueueFunc(obj runtime.Object) string {
	svcName, _ := serviceNameFromSecretEventObj(obj)
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), svcName)
}

func secretsServiceNameQueueFilter(obj interface{}) bool {
	_, ok := serviceNameFromSecretEventObj(obj)
	return ok
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

	secret := serviceToBaseSecret(serviceCopy)
	if err := regenerateServiceSecret(sc.servingCA, serviceCopy, secret); err != nil {
		return err
	}

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

func getServiceNumFailures(service *corev1.Service) int {
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

	if secretIsIssuedByCA(secret, corev1.TLSCertKey, sc.servingCA) {
		return false
	}

	// we have failed too many times on this service, give up
	if getServiceNumFailures(service) >= sc.maxRetries {
		return false
	}

	// the secret exists but the service was either not updated to include the correct created
	// by annotation or it does not match what we expect (i.e. the certificate has been rotated)
	return true
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
	if updateErr == nil && getServiceNumFailures(service) >= sc.maxRetries {
		return nil
	}

	// Return the original error.
	return err
}

// Sets the service CA common name and clears any errors.
func (sc *serviceServingCertController) resetServiceAnnotations(service *corev1.Service) {
	service.Annotations[api.AlphaServingCertCreatedByAnnotation] = sc.servingCA.commonName()
	service.Annotations[api.ServingCertCreatedByAnnotation] = sc.servingCA.commonName()
	delete(service.Annotations, api.AlphaServingCertErrorAnnotation)
	delete(service.Annotations, api.AlphaServingCertErrorNumAnnotation)
	delete(service.Annotations, api.ServingCertErrorAnnotation)
	delete(service.Annotations, api.ServingCertErrorNumAnnotation)
}

func serviceOwnerRef(service *corev1.Service) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Service",
		Name:       service.Name,
		UID:        service.UID,
	}
}

func serviceToBaseSecret(service *corev1.Service) *corev1.Secret {
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

// MakeServiceServingCert uses ServingCA to generate a TLS certificate/private key for serviceObjectMeta.
func MakeServiceServingCert(servingCA *ServingCA, serviceObjectMeta *metav1.ObjectMeta) (*crypto.TLSCertificateConfig, error) {
	dnsName := serviceObjectMeta.Name + "." + serviceObjectMeta.Namespace + ".svc"
	return servingCA.makeServingCert(dnsName, &serviceObjectMeta.UID)
}

func regenerateServiceSecret(servingCA *ServingCA, service *corev1.Service, secretCopy *corev1.Secret) error {
	servingCert, err := MakeServiceServingCert(servingCA, &service.ObjectMeta)
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

	controller.EnsureOwnerRef(secretCopy, serviceOwnerRef(service))

	return nil
}

func setErrAnnotation(service *corev1.Service, err error) {
	service.Annotations[api.ServingCertErrorAnnotation] = err.Error()
	service.Annotations[api.AlphaServingCertErrorAnnotation] = err.Error()
}

func incrementFailureNumAnnotation(service *corev1.Service) {
	numFailure := strconv.Itoa(getServiceNumFailures(service) + 1)
	service.Annotations[api.ServingCertErrorNumAnnotation] = numFailure
	service.Annotations[api.AlphaServingCertErrorNumAnnotation] = numFailure
}

func uidsEqual(secret *corev1.Secret, service *corev1.Service) bool {
	suid := string(service.UID)
	return secret.Annotations[api.AlphaServiceUIDAnnotation] == suid ||
		secret.Annotations[api.ServiceUIDAnnotation] == suid
}
