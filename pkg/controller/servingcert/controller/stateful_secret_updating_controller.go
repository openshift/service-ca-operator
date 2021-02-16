package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	informers "k8s.io/client-go/informers/core/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	appslistersv1 "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type statefulSetServingCertUpdateController struct {
	secretClient kcoreclient.SecretsGetter

	statefulSetLister appslistersv1.StatefulSetLister
	secretLister      listers.SecretLister

	servingCA *ServingCA
	// minTimeLeftForCert is how much time is remaining for the serving cert before regenerating it.
	minTimeLeftForCert time.Duration
}

func NewStatefulSetServingCertUpdateController(
	statefulSets appsinformersv1.StatefulSetInformer,
	secrets informers.SecretInformer,
	secretClient kcoreclient.SecretsGetter,
	servingCA *ServingCA,
	recorder events.Recorder,
) factory.Controller {
	sc := &statefulSetServingCertUpdateController{
		secretClient:      secretClient,
		statefulSetLister: statefulSets.Lister(),
		secretLister:      secrets.Lister(),

		servingCA: servingCA,
		// TODO base the expiry time on a percentage of the time for the lifespan of the cert
		minTimeLeftForCert: 1 * time.Hour,
	}

	return factory.New().
		WithFilteredEventsInformersQueueKeyFunc(namespacedObjToQueueKey, secretsStatefulSetNameQueueFilter, secrets.Informer()).
		WithBareInformers(statefulSets.Informer()).
		WithSync(sc.Sync).
		ToController("StatefulSetServingCertUpdateController", recorder.WithComponentSuffix("StatefulSet-serving-cert-update-controller"))
}

func (sc *statefulSetServingCertUpdateController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	secretNS, secretName := objFromQueueKey(syncCtx.QueueKey())

	sharedSecret, err := sc.secretLister.Secrets(secretNS).Get(secretName)
	if kapierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to get secret %s/%s: %v", secretNS, secretName, err)
	}

	statefulSet := sc.getStatefulSetForSecret(sharedSecret)
	if statefulSet == nil {
		return nil
	}

	if !isSecretValidForStatefulSet(statefulSet, sharedSecret) {
		return nil
	}

	// make a copy to avoid mutating cache state
	secretCopy := sharedSecret.DeepCopy()

	// Note that this controller does not explicitly schedule secret regeneration “at the right time”;
	// apart from process startup, it completely relies on a periodic resync of all objects that the
	// controller infrastructure does, currently every 20 minutes per the parameter
	// passed to informers.NewSharedInformerFactory used to create our informers.
	if sc.requiresRegeneration(statefulSet, sharedSecret, sc.minTimeLeftForCert) {
		// Regenerate the secret
		if err := regenerateStatefulSetSecret(sc.servingCA, statefulSet, secretCopy); err != nil {
			return err
		}
		_, err := sc.secretClient.Secrets(secretCopy.Namespace).Update(ctx, secretCopy, metav1.UpdateOptions{})
		return err
	}
	// If not regenerating, perform checks here to
	// 1. ensure the right set of keys we want exist
	// 2. ensure cert data is at least a parseable certificate, if not replace with valid data
	// This does not ensure that somebody didn't swap out secret data for another valid cert.
	update, err := sc.ensureSecretData(statefulSet, secretCopy)
	if err != nil {
		return err
	}
	if update {
		_, err := sc.secretClient.Secrets(secretCopy.Namespace).Update(ctx, secretCopy, metav1.UpdateOptions{})
		return err
	}
	return nil
}

func isSecretValidForStatefulSet(sharedStatefulSet *appsv1.StatefulSet, secret *v1.Secret) bool {
	isValid := true
	if sharedStatefulSet.Annotations[api.AlphaServingCertSecretAnnotation] != secret.Name {
		isValid = false
	}
	if secret.Annotations[api.AlphaStatefulSetUIDAnnotation] != string(sharedStatefulSet.UID) {
		isValid = false
	}
	return isValid
}

func (sc *statefulSetServingCertUpdateController) getStatefulSetForSecret(sharedSecret *v1.Secret) *appsv1.StatefulSet {
	statefulSetName, ok := toStatefulSetName(sharedSecret)
	if !ok {
		return nil
	}
	statefulSet, err := sc.statefulSetLister.StatefulSets(sharedSecret.Namespace).Get(statefulSetName)
	if kapierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get StatefulSet %s/%s: %v", sharedSecret.Namespace, statefulSetName, err))
		return nil
	}
	return statefulSet
}

func (sc *statefulSetServingCertUpdateController) requiresRegeneration(statefulSet *appsv1.StatefulSet, secret *v1.Secret, minTimeLeft time.Duration) bool {
	return secretRequiresRegeneration(secret, statefulSetOwnerRef(statefulSet), minTimeLeft)
}

func (sc *statefulSetServingCertUpdateController) ensureSecretData(statefulSet *appsv1.StatefulSet, secretCopy *v1.Secret) (bool, error) {
	existingCerts := statefulSetSecretCount(secretCopy)
	// We don’t care about comparing existingCerts with the desired value
	// (including the case when some key/certificate has been manually removed);
	// statefulSetServingController is responsible for that.

	update := false
	if len(secretCopy.Data) != 2*existingCerts {
		// There are some extra data fields; drop them.
		oldData := secretCopy.Data
		secretCopy.Data = map[string][]byte{}
		for i := 0; i < existingCerts; i++ {
			certName, keyName := statefulSetCertKeyFilenames(i)
			secretCopy.Data[certName] = oldData[certName]
			secretCopy.Data[keyName] = oldData[keyName]
		}
		update = true
	}

	// This ensures someone did not replace secret cert data with ascii art
	// Check for valid cert data, replace with valid data if not
	for i := 0; i < existingCerts; i++ {
		certName, _ := statefulSetCertKeyFilenames(i)
		block, _ := pem.Decode(secretCopy.Data[certName])
		if block == nil {
			// Regenerate the secret
			klog.Infof("Error decoding cert bytes %s from secret: %s namespace: %s, replacing cert", certName, secretCopy.Name, secretCopy.Namespace)
			// Regenerate the secret
			if err := regenerateStatefulSetSecret(sc.servingCA, statefulSet, secretCopy); err != nil {
				return update, err
			}
			return true, nil
		}
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			klog.Infof("Error parsing %s from secret: %s namespace: %s, replacing cert", certName, secretCopy.Name, secretCopy.Namespace)
			// Regenerate the secret
			if err := regenerateStatefulSetSecret(sc.servingCA, statefulSet, secretCopy); err != nil {
				return update, err
			}
			return true, nil
		}
	}
	return update, nil
}
