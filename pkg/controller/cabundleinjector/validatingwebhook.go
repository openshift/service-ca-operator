package cabundleinjector

import (
	"bytes"
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	admissionreglister "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type validatingWebhookCABundleInjector struct {
	client   admissionregclient.ValidatingWebhookConfigurationInterface
	lister   admissionreglister.ValidatingWebhookConfigurationLister
	caBundle []byte
}

func newValidatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().ValidatingWebhookConfigurations()
	syncer := &validatingWebhookCABundleInjector{
		client:   config.kubeClient.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:     "ValidatingWebhookCABundleInjector",
		sync:     syncer.Sync,
		informer: informer.Informer(),
		annotationsChecker: annotationsChecker(
			api.InjectCABundleAnnotationName,
		),
	}
}

func (bi *validatingWebhookCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	webhookConfig, err := bi.lister.Get(syncCtx.QueueKey())
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

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
	_, err = bi.client.Update(context.TODO(), webhookConfigCopy, metav1.UpdateOptions{})
	return err
}
