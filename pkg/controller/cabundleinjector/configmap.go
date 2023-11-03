package cabundleinjector

import (
	"context"

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

type configMapCABundleInjector struct {
	client   kcoreclient.ConfigMapsGetter
	lister   listers.ConfigMapLister
	caBundle string

	filterFn func(configMap *corev1.ConfigMap) bool
}

func newConfigMapInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Core().V1().ConfigMaps()

	syncer := &configMapCABundleInjector{
		client:   config.kubeClient.CoreV1(),
		lister:   informer.Lister(),
		caBundle: string(config.caBundle),
	}

	return controllerConfig{
		name:     "ConfigMapCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		annotationsChecker: annotationsChecker(
			api.InjectCABundleAnnotationName,
			api.AlphaInjectCABundleAnnotationName,
		),
		namespaced: true,
	}
}

// newVulnerableLegacyConfigMapInjectorConfig injects a configmap that contains more certificates than are required to
// verify service serving certificates.
func newVulnerableLegacyConfigMapInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Core().V1().ConfigMaps()

	syncer := &configMapCABundleInjector{
		client:   config.kubeClient.CoreV1(),
		lister:   informer.Lister(),
		caBundle: string(config.legacyVulnerableCABundle),

		// only set content for the one configmap that we are required to for backward compatibility.  This limits the
		// future potential for abuse.
		filterFn: func(configMap *corev1.ConfigMap) bool {
			// if either of the preferred annotations are present, the legacy injector needs to stand down and allow
			// the preferred injector to take over.  This avoids dueling updates.
			if _, ok := configMap.Annotations[api.InjectCABundleAnnotationName]; ok {
				return false
			}
			if _, ok := configMap.Annotations[api.AlphaInjectCABundleAnnotationName]; ok {
				return false
			}

			if configMap.Name == "openshift-service-ca.crt" {
				return true
			}
			return false
		},
	}

	return controllerConfig{
		name:     "LegacyVulnerableConfigMapCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		annotationsChecker: annotationsChecker(
			api.VulnerableLegacyInjectCABundleAnnotationName,
		),
		namespaced: true,
	}
}

func (bi *configMapCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	namespace, name := namespacedObjectFromQueueKey(syncCtx.QueueKey())

	configMap, err := bi.lister.ConfigMaps(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	if bi.filterFn != nil && !bi.filterFn(configMap) {
		return nil
	}

	// skip updating when the CA bundle is already there
	if data, ok := configMap.Data[api.InjectionDataKey]; ok &&
		data == bi.caBundle && len(configMap.Data) == 1 {

		return nil
	}

	klog.Infof("updating configmap %s/%s with the service signing CA bundle", configMap.Namespace, configMap.Name)

	// make a copy to avoid mutating cache state
	configMapCopy := configMap.DeepCopy()
	configMapCopy.Data = map[string]string{api.InjectionDataKey: bi.caBundle}
	// set the owning-component unless someone else has claimed it.
	if len(configMapCopy.Annotations[apiannotations.OpenShiftComponent]) == 0 {
		configMapCopy.Annotations[apiannotations.OpenShiftComponent] = api.OwningJiraComponent
	}

	_, err = bi.client.ConfigMaps(configMapCopy.Namespace).Update(ctx, configMapCopy, metav1.UpdateOptions{})
	return err
}
