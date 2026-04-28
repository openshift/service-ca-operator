package cabundleinjector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	apiannotations "github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type secretCABundleInjector struct {
	client   kcoreclient.SecretsGetter
	lister   listers.SecretLister
	caBundle string

	filterFn func(secret *corev1.Secret) bool
}

func newSecretInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Core().V1().Secrets()

	syncer := &secretCABundleInjector{
		client:   config.kubeClient.CoreV1(),
		lister:   informer.Lister(),
		caBundle: string(config.caBundle),
	}

	return controllerConfig{
		name:     "SecretCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		annotationsChecker: annotationsChecker(
			api.InjectCABundleAnnotationName,
		),
		namespaced: true,
	}
}

func (bi *secretCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	namespace, name := namespacedObjectFromQueueKey(syncCtx.QueueKey())

	secret, err := bi.lister.Secrets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if bi.filterFn != nil && !bi.filterFn(secret) {
		return nil
	}

	// skip updating when the CA bundle is already there
	if data, ok := secret.Data[api.InjectionDataKey]; ok &&
		string(data) == bi.caBundle && len(secret.Data) == 1 {

		return nil
	}

	klog.Infof("updating secret %s/%s with the service signing CA bundle", secret.Namespace, secret.Name)

	// make a copy to avoid mutating cache state
	secretCopy := secret.DeepCopy()
	secretCopy.Data = map[string][]byte{api.InjectionDataKey: []byte(bi.caBundle)}
	// set the owning-component unless someone else has claimed it.
	if len(secretCopy.Annotations[apiannotations.OpenShiftComponent]) == 0 {
		secretCopy.Annotations[apiannotations.OpenShiftComponent] = api.OwningJiraComponent
		secretCopy.Annotations[apiannotations.OpenShiftDescription] = fmt.Sprintf("Secret is added/updated with a data item containing the CA signing bundle that can be used to verify service-serving certificates")
	}

	_, err = bi.client.Secrets(secretCopy.Namespace).Update(ctx, secretCopy, metav1.UpdateOptions{})
	return err
}
