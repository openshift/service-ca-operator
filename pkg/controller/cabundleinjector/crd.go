package cabundleinjector

import (
	"bytes"
	"context"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextclientv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apiextinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	apiextlister "k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type crdCABundleInjector struct {
	client   apiextclientv1.CustomResourceDefinitionInterface
	lister   apiextlister.CustomResourceDefinitionLister
	caBundle []byte
}

func newCRDInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	client := apiextclient.NewForConfigOrDie(config.config)
	informers := apiextinformer.NewSharedInformerFactory(client, config.defaultResync)
	informer := informers.Apiextensions().V1().CustomResourceDefinitions()
	keySyncer := &crdCABundleInjector{
		client:   client.ApiextensionsV1().CustomResourceDefinitions(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:           "CRDCABundleInjector",
		keySyncer:      keySyncer,
		informerGetter: informer,
		startInformers: func(stopChan <-chan struct{}) {
			informers.Start(stopChan)
		},
		supportedAnnotations: []string{
			api.InjectCABundleAnnotationName,
		},
	}
}

func (bi *crdCABundleInjector) Key(namespace, name string) (metav1.Object, error) {
	return bi.lister.Get(name)
}

func (bi *crdCABundleInjector) Sync(obj metav1.Object) error {
	crd := obj.(*apiext.CustomResourceDefinition)

	if crd.Spec.Conversion == nil {
		klog.Warningf("customresourcedefinition %s is annotated for ca bundle injection but spec.conversion is not specified", crd.Name)
		return nil
	}
	if crd.Spec.Conversion.Strategy != apiext.WebhookConverter {
		klog.Warningf("customresourcedefinition %s is annotated for ca bundle injection but does not use strategy %q", crd.Name, apiext.WebhookConverter)
		return nil
	}
	if bytes.Equal(crd.Spec.Conversion.Webhook.ClientConfig.CABundle, bi.caBundle) {
		// up-to-date
		return nil
	}

	klog.Infof("updating customresourcedefinition %s conversion webhook config with the service signing CA bundle", crd.Name)

	// make a copy to avoid mutating cache state
	crdCopy := crd.DeepCopy()
	crdCopy.Spec.Conversion.Webhook.ClientConfig.CABundle = bi.caBundle
	_, err := bi.client.Update(context.TODO(), crdCopy, metav1.UpdateOptions{})
	return err
}
