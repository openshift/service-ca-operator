package cabundleinjector

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kcoreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type configMapCABundleInjector struct {
	client   kcoreclient.ConfigMapsGetter
	lister   listers.ConfigMapLister
	caBundle string
}

func newConfigMapInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Core().V1().ConfigMaps()

	keySyncer := &configMapCABundleInjector{
		client:   config.kubeClient.CoreV1(),
		lister:   informer.Lister(),
		caBundle: string(config.caBundle),
	}

	return controllerConfig{
		name:           "ConfigMapCABundleInjector",
		keySyncer:      keySyncer,
		informerGetter: informer,
	}
}

func (bi *configMapCABundleInjector) Key(namespace, name string) (metav1.Object, error) {
	return bi.lister.ConfigMaps(namespace).Get(name)
}

func (bi *configMapCABundleInjector) Sync(obj metav1.Object) error {
	configMap := obj.(*corev1.ConfigMap)

	// skip updating when the CA bundle is already there
	if data, ok := configMap.Data[api.InjectionDataKey]; ok &&
		data == bi.caBundle && len(configMap.Data) == 1 {

		return nil
	}

	klog.Infof("updating configmap %s/%s with the service signing CA bundle", configMap.Namespace, configMap.Name)

	// make a copy to avoid mutating cache state
	configMapCopy := configMap.DeepCopy()
	configMapCopy.Data = map[string]string{api.InjectionDataKey: bi.caBundle}
	_, err := bi.client.ConfigMaps(configMapCopy.Namespace).Update(configMapCopy)
	return err
}
