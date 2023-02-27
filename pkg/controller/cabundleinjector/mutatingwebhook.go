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

type mutatingWebhookCABundleInjector struct {
	client   admissionregclient.MutatingWebhookConfigurationInterface
	lister   admissionreglister.MutatingWebhookConfigurationLister
	caBundle []byte
}

func newMutatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().MutatingWebhookConfigurations()
	syncer := &mutatingWebhookCABundleInjector{
		client:   config.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		lister:   informer.Lister(),
		caBundle: config.caBundle,
	}
	return controllerConfig{
		name:               "MutatingWebhookCABundleInjector",
		sync:               syncer.Sync,
		informer:           informer.Informer(),
		annotationsChecker: annotationsChecker(api.InjectCABundleAnnotationName),
	}
}

func (bi *mutatingWebhookCABundleInjector) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
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

	klog.Infof("updating mutatingwebhookconfiguration %s with the service signing CA bundle", webhookConfig.Name)

	// make a copy to avoid mutating cache state
	webhookConfigCopy := webhookConfig.DeepCopy()
	for _, i := range webhooksNeedingUpdate {
		webhookConfigCopy.Webhooks[i].ClientConfig.CABundle = bi.caBundle
	}
	_, err = bi.client.Update(ctx, webhookConfigCopy, metav1.UpdateOptions{})
	return err
}
