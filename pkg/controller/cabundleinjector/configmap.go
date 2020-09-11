package cabundleinjector

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type configMapCABundleInjector struct {
	client   kcoreclient.ConfigMapsGetter
	lister   listers.ConfigMapLister
	caBundle string
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

func (bi *configMapCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	namespace, name := namespacedObjectFromQueueKey(syncCtx.QueueKey())

	configMap, err := bi.lister.ConfigMaps(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
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
	_, err = bi.client.ConfigMaps(configMapCopy.Namespace).Update(ctx, configMapCopy, metav1.UpdateOptions{})
	return err
}
