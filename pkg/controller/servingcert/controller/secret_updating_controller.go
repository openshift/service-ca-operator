package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	informers "k8s.io/client-go/informers/core/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	ocontroller "github.com/openshift/library-go/pkg/controller"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type serviceServingCertUpdateController struct {
	secretClient kcoreclient.SecretsGetter

	serviceLister listers.ServiceLister
	secretLister  listers.SecretLister

	ca                 *crypto.CA
	intermediateCACert *x509.Certificate
	dnsSuffix          string
	// minTimeLeftForCert is how much time is remaining for the serving cert before regenerating it.
	minTimeLeftForCert time.Duration
}

func NewServiceServingCertUpdateController(
	services informers.ServiceInformer,
	secrets informers.SecretInformer,
	secretClient kcoreclient.SecretsGetter,
	ca *crypto.CA,
	intermediateCACert *x509.Certificate,
	dnsSuffix string,
	recorder events.Recorder,
) factory.Controller {
	sc := &serviceServingCertUpdateController{
		secretClient:  secretClient,
		serviceLister: services.Lister(),
		secretLister:  secrets.Lister(),

		ca:                 ca,
		intermediateCACert: intermediateCACert,
		dnsSuffix:          dnsSuffix,
		// TODO base the expiry time on a percentage of the time for the lifespan of the cert
		minTimeLeftForCert: 1 * time.Hour,
	}

	return factory.New().
		WithFilteredEventsInformersQueueKeyFunc(namespacedObjToQueueKey, secretsQueueFilter, secrets.Informer()).
		WithBareInformers(services.Informer()).
		WithSync(sc.Sync).
		ToController("ServiceServingCertUpdateController", recorder.WithComponentSuffix("service-serving-cert-update-controller"))
}

func (sc *serviceServingCertUpdateController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	secretNS, secretName := objFromQueueKey(syncCtx.QueueKey())

	sharedSecret, err := sc.secretLister.Secrets(secretNS).Get(secretName)
	if kapierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to get secret %s/%s: %v", secretNS, secretName, err)
	}

	service := sc.getServiceForSecret(sharedSecret)
	if service == nil {
		return nil
	}

	if !isSecretValidForService(service, sharedSecret) {
		return nil
	}

	// make a copy to avoid mutating cache state
	secretCopy := sharedSecret.DeepCopy()

	if sc.requiresRegeneration(service, sharedSecret, sc.minTimeLeftForCert) {
		// Regenerate the secret
		if err := toRequiredSecret(sc.dnsSuffix, sc.ca, sc.intermediateCACert, service, secretCopy); err != nil {
			return err
		}
		_, err := sc.secretClient.Secrets(secretCopy.Namespace).Update(ctx, secretCopy, metav1.UpdateOptions{})
		return err
	}
	// If not regenerating, perform checks here to
	// 1. ensure only the 2 data keys we want exist, TLSCertKey and TLSPrivateKeyKey
	// 2. ensure cert data is at least a parseable certificate, if not replace with valid data
	// This does not ensure that somebody didn't swap out secret data for another valid cert.
	update, err := sc.ensureSecretData(service, secretCopy)
	if err != nil {
		return err
	}
	if update {
		_, err := sc.secretClient.Secrets(secretCopy.Namespace).Update(ctx, secretCopy, metav1.UpdateOptions{})
		return err
	}
	return nil
}

func isSecretValidForService(sharedService *v1.Service, secret *v1.Secret) bool {
	isValid := true
	if sharedService.Annotations[api.ServingCertSecretAnnotation] != secret.Name && sharedService.Annotations[api.AlphaServingCertSecretAnnotation] != secret.Name {
		isValid = false
	}
	if secret.Annotations[api.ServiceUIDAnnotation] != string(sharedService.UID) && secret.Annotations[api.AlphaServiceUIDAnnotation] != string(sharedService.UID) {
		isValid = false
	}
	return isValid
}

func (sc *serviceServingCertUpdateController) getServiceForSecret(sharedSecret *v1.Secret) *v1.Service {
	serviceName, ok := toServiceName(sharedSecret)
	if !ok {
		return nil
	}
	service, err := sc.serviceLister.Services(sharedSecret.Namespace).Get(serviceName)
	if kapierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get service %s/%s: %v", sharedSecret.Namespace, serviceName, err))
		return nil
	}
	return service
}

func (sc *serviceServingCertUpdateController) requiresRegeneration(service *v1.Service, secret *v1.Secret, minTimeLeft time.Duration) bool {
	// if we don't have an ownerref, just go ahead and regenerate.  It's easier than writing a
	// secondary logic flow.
	if !ocontroller.HasOwnerRef(secret, ownerRef(service)) {
		return true
	}
	// if we don't have the annotation for expiry, just go ahead and regenerate.  It's easier than writing a
	// secondary logic flow that creates the expiry dates
	expiryString, ok := secret.Annotations[api.ServingCertExpiryAnnotation]
	if !ok {
		expiryString, ok = secret.Annotations[api.AlphaServingCertExpiryAnnotation]
		if !ok {
			return true
		}
	}
	expiry, err := time.Parse(time.RFC3339, expiryString)
	if err != nil {
		return true
	}

	if time.Now().Add(minTimeLeft).After(expiry) {
		return true
	}

	return false
}

func (sc *serviceServingCertUpdateController) ensureSecretData(service *v1.Service, secretCopy *v1.Secret) (bool, error) {
	update := false
	tlsCert, ok := secretCopy.Data[v1.TLSCertKey]
	tlsKey, ok2 := secretCopy.Data[v1.TLSPrivateKeyKey]
	if ok && ok2 {
		// Don't update, replace unless len data is not 2
		// This takes care of case where someone added an extra data field. Remove all but 2 keys
		if len(secretCopy.Data) != 2 {
			// don't regenerate, just get rid of bad data
			secretCopy.Data = map[string][]byte{
				v1.TLSCertKey:       tlsCert,
				v1.TLSPrivateKeyKey: tlsKey,
			}
			update = true
		}
	} else {
		// if required tlscertkey,tlsprivatekey fields missing, replace with valid secret
		// Regenerate the secret
		if err := toRequiredSecret(sc.dnsSuffix, sc.ca, sc.intermediateCACert, service, secretCopy); err != nil {
			return update, err
		}
		return true, nil
	}
	// This ensures someone did not replace secret cert data with ascii art
	// Check for valid cert data, replace with valid data if not
	block, _ := pem.Decode([]byte(tlsCert))
	if block == nil {
		// Regenerate the secret
		klog.Infof("Error decoding cert bytes %s from secret: %s namespace: %s, replacing cert", v1.TLSCertKey, secretCopy.Name, secretCopy.Namespace)
		// Regenerate the secret
		if err := toRequiredSecret(sc.dnsSuffix, sc.ca, sc.intermediateCACert, service, secretCopy); err != nil {
			return update, err
		}
		return true, nil
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		klog.Infof("Error parsing %s from secret: %s namespace: %s, replacing cert", v1.TLSCertKey, secretCopy.Name, secretCopy.Namespace)
		// Regenerate the secret
		if err := toRequiredSecret(sc.dnsSuffix, sc.ca, sc.intermediateCACert, service, secretCopy); err != nil {
			return update, err
		}
		return true, nil
	}
	return update, nil
}

func toServiceName(secret *v1.Secret) (string, bool) {
	serviceName := secret.Annotations[api.ServiceNameAnnotation]
	if len(serviceName) == 0 {
		serviceName = secret.Annotations[api.AlphaServiceNameAnnotation]
	}
	return serviceName, len(serviceName) != 0
}
