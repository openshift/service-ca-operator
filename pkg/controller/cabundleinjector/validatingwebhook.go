package cabundleinjector

import (
	"bytes"
	"context"

	admissionreg "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	admissionreglister "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/klog"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type validatingWebhookCABundleInjector struct {
	client   admissionregclient.ValidatingWebhookConfigurationInterface
	lister   admissionreglister.ValidatingWebhookConfigurationLister
	caBundle []byte
}

func newValidatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().ValidatingWebhookConfigurations()
	keySyncer := &validatingWebhookCABundleInjector{
		client:   config.kubeClient.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:           "ValidatingWebhookCABundleInjector",
		keySyncer:      keySyncer,
		informerGetter: informer,
		supportedAnnotations: []string{
			api.InjectCABundleAnnotationName,
		},
	}
}

func (bi *validatingWebhookCABundleInjector) Key(namespace, name string) (metav1.Object, error) {
	return bi.lister.Get(name)
}

func (bi *validatingWebhookCABundleInjector) Sync(obj metav1.Object) error {
	webhookConfig := obj.(*admissionreg.ValidatingWebhookConfiguration)

	webhooksNeedingUpdate := []int{}
	for i, webhook := range webhookConfig.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, bi.caBundle) {
			webhooksNeedingUpdate = append(webhooksNeedingUpdate, i)
		}
	}
	if len(webhooksNeedingUpdate) == 0 {
		return nil
	}

	klog.Infof("updating validatingwebhookconfiguration %s with the service signing CA bundle", webhookConfig.Name)

	// make a copy to avoid mutating cache state
	webhookConfigCopy := webhookConfig.DeepCopy()
	for i := range webhooksNeedingUpdate {
		webhookConfigCopy.Webhooks[i].ClientConfig.CABundle = bi.caBundle
	}
	_, err := bi.client.Update(context.TODO(), webhookConfigCopy, metav1.UpdateOptions{})
	return err
}
