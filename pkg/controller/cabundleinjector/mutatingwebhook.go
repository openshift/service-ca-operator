package cabundleinjector

import (
	"bytes"
	"context"

	admissionreg "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	admissionreglister "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type mutatingWebhookCABundleInjector struct {
	client   admissionregclient.MutatingWebhookConfigurationInterface
	lister   admissionreglister.MutatingWebhookConfigurationLister
	caBundle []byte
}

func newMutatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().MutatingWebhookConfigurations()
	keySyncer := &mutatingWebhookCABundleInjector{
		client:   config.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:           "MutatingWebhookCABundleInjector",
		keySyncer:      keySyncer,
		informerGetter: informer,
		supportedAnnotations: []string{
			api.InjectCABundleAnnotationName,
		},
	}
}

func (bi *mutatingWebhookCABundleInjector) Key(namespace, name string) (metav1.Object, error) {
	return bi.lister.Get(name)
}

func (bi *mutatingWebhookCABundleInjector) Sync(obj metav1.Object) error {
	webhookConfig := obj.(*admissionreg.MutatingWebhookConfiguration)

	webhooksNeedingUpdate := []int{}
	for i, webhook := range webhookConfig.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, bi.caBundle) {
			webhooksNeedingUpdate = append(webhooksNeedingUpdate, i)
		}
	}
	if len(webhooksNeedingUpdate) == 0 {
		return nil
	}

	klog.Infof("updating mutatingwebhookconfiguration %s with the service signing CA bundle", webhookConfig.Name)

	// make a copy to avoid mutating cache state
	webhookConfigCopy := webhookConfig.DeepCopy()
	for i := range webhooksNeedingUpdate {
		webhookConfigCopy.Webhooks[i].ClientConfig.CABundle = bi.caBundle
	}
	_, err := bi.client.Update(context.TODO(), webhookConfigCopy, metav1.UpdateOptions{})
	return err
}
