package controller

import (
	"context"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	informers "k8s.io/client-go/informers/core/v1"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	appslistersv1 "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type statefulSetServingCertController struct {
	statefulSetClient appsclientv1.StatefulSetsGetter
	secretClient      kcoreclient.SecretsGetter

	statefulSetLister appslistersv1.StatefulSetLister
	secretLister      listers.SecretLister

	servingCA  *ServingCA
	maxRetries int
}

func NewStatefulSetServingCertController(
	statefulSets appsinformersv1.StatefulSetInformer,
	secrets informers.SecretInformer,
	statefulSetClient appsclientv1.StatefulSetsGetter,
	secretClient kcoreclient.SecretsGetter,
	servingCA *ServingCA,
	recorder events.Recorder,
) factory.Controller {
	sc := &statefulSetServingCertController{
		statefulSetClient: statefulSetClient,
		secretClient:      secretClient,

		statefulSetLister: statefulSets.Lister(),
		secretLister:      secrets.Lister(),

		servingCA:  servingCA,
		maxRetries: 10,
	}

	return factory.New().
		WithInformersQueueKeyFunc(namespacedObjToQueueKey, statefulSets.Informer()).
		WithFilteredEventsInformersQueueKeyFunc(statefulSetFromSecretQueueFunc, secretsStatefulSetNameQueueFilter, secrets.Informer()).
		WithSync(sc.Sync).
		ToController("StatefulSetServingCertController", recorder.WithComponentSuffix("StatefulSet-serving-cert-controller"))
}

func (sc *statefulSetServingCertController) Sync(ctx context.Context, syncContext factory.SyncContext) error {
	statefulSetNS, statefulSetName := objFromQueueKey(syncContext.QueueKey())

	sharedStatefulSet, err := sc.statefulSetLister.StatefulSets(statefulSetNS).Get(statefulSetName)
	if kapierrors.IsNotFound(err) {
		klog.V(4).Infof("statefulSet %s/%s not found", statefulSetNS, statefulSetName)
		return nil
	} else if err != nil {
		return fmt.Errorf("unable to get statefulSet %s/%s: %v", statefulSetNS, statefulSetName, err)
	}

	if !sc.requiresCertGeneration(sharedStatefulSet) {
		return nil
	}

	// make a copy to avoid mutating cache state
	statefulSetCopy := sharedStatefulSet.DeepCopy()
	return sc.generateCert(ctx, statefulSetCopy)
}

func (sc *statefulSetServingCertController) generateCert(ctx context.Context, statefulSetCopy *appsv1.StatefulSet) error {
	klog.V(4).Infof("generating new cert for %s/%s", statefulSetCopy.GetNamespace(), statefulSetCopy.GetName())
	if statefulSetCopy.Annotations == nil {
		statefulSetCopy.Annotations = map[string]string{}
	}

	secret := statefulSetToBaseSecret(statefulSetCopy)
	if err := regenerateStatefulSetSecret(sc.servingCA, statefulSetCopy, secret); err != nil {
		return err
	}

	_, err := sc.secretClient.Secrets(statefulSetCopy.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !kapierrors.IsAlreadyExists(err) {
		return sc.updateStatefulSetFailure(ctx, statefulSetCopy, err)
	}
	if kapierrors.IsAlreadyExists(err) {
		actualSecret, err := sc.secretClient.Secrets(statefulSetCopy.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return sc.updateStatefulSetFailure(ctx, statefulSetCopy, err)
		}

		if actualSecret.Annotations[api.AlphaStatefulSetUIDAnnotation] != string(statefulSetCopy.UID) {
			uidErr := fmt.Errorf("secret %s/%s does not have corresponding StatefulSet UID %v", actualSecret.GetNamespace(), actualSecret.GetName(), statefulSetCopy.UID)
			return sc.updateStatefulSetFailure(ctx, statefulSetCopy, uidErr)
		}
		klog.V(4).Infof("renewing cert in existing secret %s/%s", secret.GetNamespace(), secret.GetName())
		// Actually update the secret in the regeneration case (the secret already exists but we want to update to a new cert).
		_, updateErr := sc.secretClient.Secrets(secret.GetNamespace()).Update(ctx, secret, metav1.UpdateOptions{})
		if updateErr != nil {
			return sc.updateStatefulSetFailure(ctx, statefulSetCopy, updateErr)
		}
	}

	sc.resetStatefulSetAnnotations(statefulSetCopy)
	_, err = sc.statefulSetClient.StatefulSets(statefulSetCopy.Namespace).Update(ctx, statefulSetCopy, metav1.UpdateOptions{})

	return err
}

func getStatefulSetNumFailures(statefulSet *appsv1.StatefulSet) int {
	numFailuresString := statefulSet.Annotations[api.AlphaServingCertErrorNumAnnotation]
	if len(numFailuresString) == 0 {
		return 0
	}

	numFailures, err := strconv.Atoi(numFailuresString)
	if err != nil {
		return 0
	}

	return numFailures
}

func (sc *statefulSetServingCertController) requiresCertGeneration(statefulSet *appsv1.StatefulSet) bool {
	// check the secret since it could not have been created yet
	secretName := statefulSet.Annotations[api.AlphaServingCertSecretAnnotation]
	if len(secretName) == 0 {
		return false
	}

	shouldUpdate := false // Is there anything we would like to do?
	secret, err := sc.secretLister.Secrets(statefulSet.Namespace).Get(secretName)
	if kapierrors.IsNotFound(err) {
		shouldUpdate = true // We have not created the secret yet
	} else if err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to get the secret %s/%s: %v", statefulSet.Namespace, secretName, err))
		return false
	} else { // secret is valid
		// Regenerate if we need more secrets. If we have enough secrets and the StatefulSet is scaled
		// down, don’t bother modifying the secret — we’ll eventually regenerate a smaller one on expiration.
		if statefulSetSecretCount(secret) < desiredCertsForStatefulSetSecret(statefulSet) {
			shouldUpdate = true // We need to add more secrets
		} else {
			firstCertName, _ := statefulSetCertKeyFilenames(0)
			if !secretIsIssuedByCA(secret, firstCertName, sc.servingCA) {
				shouldUpdate = true // The secret does not match what we expect (i.e. the certificate has been rotated)
			}
		}
	}
	// Nothing to do
	if !shouldUpdate {
		return false
	}

	// we have failed too many times on this StatefulSet, give up
	if getStatefulSetNumFailures(statefulSet) >= sc.maxRetries {
		return false
	}

	return true
}

// updateStatefulSetFailure updates the StatefulSet's error annotations with err.
// Returns the passed in err normally, or nil if the amount of failures has hit the max. This is so it can act as a
// return to the sync method.
func (sc *statefulSetServingCertController) updateStatefulSetFailure(ctx context.Context, statefulSet *appsv1.StatefulSet, err error) error {
	statefulSet.Annotations[api.AlphaServingCertErrorAnnotation] = err.Error()
	numFailures := strconv.Itoa(getStatefulSetNumFailures(statefulSet) + 1)
	statefulSet.Annotations[api.AlphaServingCertErrorNumAnnotation] = numFailures
	_, updateErr := sc.statefulSetClient.StatefulSets(statefulSet.Namespace).Update(ctx, statefulSet, metav1.UpdateOptions{})
	if updateErr != nil {
		klog.V(4).Infof("warning: failed to update failure annotations on StatefulSet %s: %v", statefulSet.Name, updateErr)
	}
	// Past the max retries means we've handled this failure enough, so forget it from the queue.
	if updateErr == nil && getStatefulSetNumFailures(statefulSet) >= sc.maxRetries {
		return nil
	}

	// Return the original error.
	return err
}

// Sets the service CA common name and clears any errors.
func (sc *statefulSetServingCertController) resetStatefulSetAnnotations(statefulSet *appsv1.StatefulSet) {
	statefulSet.Annotations[api.AlphaServingCertCreatedByAnnotation] = sc.servingCA.commonName()
	delete(statefulSet.Annotations, api.AlphaServingCertErrorAnnotation)
	delete(statefulSet.Annotations, api.AlphaServingCertErrorNumAnnotation)
}

func statefulSetToBaseSecret(statefulSet *appsv1.StatefulSet) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSet.Annotations[api.AlphaServingCertSecretAnnotation],
			Namespace: statefulSet.Namespace,
			Annotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  string(statefulSet.UID),
				api.AlphaStatefulSetNameAnnotation: statefulSet.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
	}
}
