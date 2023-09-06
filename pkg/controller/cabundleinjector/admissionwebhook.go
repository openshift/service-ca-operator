package cabundleinjector

import (
	"bytes"
	"context"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

// webhookConfigAccessor provides a common interface we can use in order to inject
// the CAs in both the validating and mutating webhookconfig objects
type webhookConfigAccessor[T admissionregv1.MutatingWebhookConfiguration | admissionregv1.ValidatingWebhookConfiguration] interface {
	metav1.Object
	GetWebhookClientCA(index int) *admissionregv1.WebhookClientConfig
	WebhooksLen() int
	DeepCopy() webhookConfigAccessor[T]
	GetObject() *T
}

type mutatingWebhookConfigAccessor struct {
	*admissionregv1.MutatingWebhookConfiguration
}

func newMutatingWebhookAccessor(webhookConfig *admissionregv1.MutatingWebhookConfiguration) webhookConfigAccessor[admissionregv1.MutatingWebhookConfiguration] {
	return &mutatingWebhookConfigAccessor{webhookConfig}
}

func (a *mutatingWebhookConfigAccessor) GetWebhookClientCA(index int) *admissionregv1.WebhookClientConfig {
	return &a.MutatingWebhookConfiguration.Webhooks[index].ClientConfig
}

func (a *mutatingWebhookConfigAccessor) WebhooksLen() int {
	return len(a.MutatingWebhookConfiguration.Webhooks)
}

func (a *mutatingWebhookConfigAccessor) DeepCopy() webhookConfigAccessor[admissionregv1.MutatingWebhookConfiguration] {
	return &mutatingWebhookConfigAccessor{
		MutatingWebhookConfiguration: a.MutatingWebhookConfiguration.DeepCopy(),
	}
}

func (a *mutatingWebhookConfigAccessor) GetObject() *admissionregv1.MutatingWebhookConfiguration {
	return a.MutatingWebhookConfiguration
}

type validatingWebhookConfigAccessor struct {
	*admissionregv1.ValidatingWebhookConfiguration
}

func newValidatingWebhookAccessor(webhookConfig *admissionregv1.ValidatingWebhookConfiguration) webhookConfigAccessor[admissionregv1.ValidatingWebhookConfiguration] {
	return &validatingWebhookConfigAccessor{webhookConfig}
}

func (a *validatingWebhookConfigAccessor) GetWebhookClientCA(index int) *admissionregv1.WebhookClientConfig {
	return &a.ValidatingWebhookConfiguration.Webhooks[index].ClientConfig
}

func (a *validatingWebhookConfigAccessor) WebhooksLen() int {
	return len(a.ValidatingWebhookConfiguration.Webhooks)
}

func (a *validatingWebhookConfigAccessor) DeepCopy() webhookConfigAccessor[admissionregv1.ValidatingWebhookConfiguration] {
	return &validatingWebhookConfigAccessor{
		ValidatingWebhookConfiguration: a.ValidatingWebhookConfiguration.DeepCopy(),
	}
}

func (a *validatingWebhookConfigAccessor) GetObject() *admissionregv1.ValidatingWebhookConfiguration {
	return a.ValidatingWebhookConfiguration
}

type cachedWebhookConfigGetter[T admissionregv1.MutatingWebhookConfiguration | admissionregv1.ValidatingWebhookConfiguration] interface {
	Get(name string) (*T, error)
}

type webhookConfigUpdater[T admissionregv1.MutatingWebhookConfiguration | admissionregv1.ValidatingWebhookConfiguration] interface {
	Update(ctx context.Context, webhookConfig *T, updateOptions metav1.UpdateOptions) (*T, error)
}

// webhookCABundleInjector creates a controller that injects the service-ca bundle
// to validating and mutating webhookconfigurations
type webhookCABundleInjector[T admissionregv1.MutatingWebhookConfiguration | admissionregv1.ValidatingWebhookConfiguration] struct {
	webhookConfigType        string
	client                   webhookConfigUpdater[T]
	lister                   cachedWebhookConfigGetter[T]
	newWebhookConfigAccessor func(*T) webhookConfigAccessor[T]
	caBundle                 []byte
}

func (bi *webhookCABundleInjector[T]) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	webhookConfig, err := bi.lister.Get(syncCtx.QueueKey())
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	webhookConfigAccessor := bi.newWebhookConfigAccessor(webhookConfig)

	webhooksNeedingUpdate := []int{}
	for i := 0; i < webhookConfigAccessor.WebhooksLen(); i++ {
		webhookClientConfig := webhookConfigAccessor.GetWebhookClientCA(i)
		if !bytes.Equal(webhookClientConfig.CABundle, bi.caBundle) {
			webhooksNeedingUpdate = append(webhooksNeedingUpdate, i)
		}
	}
	if len(webhooksNeedingUpdate) == 0 {
		return nil
	}

	klog.Infof("updating %s %s with the service signing CA bundle", bi.webhookConfigType, webhookConfigAccessor.GetName())

	// make a copy to avoid mutating cache state
	webhookConfigCopy := webhookConfigAccessor.DeepCopy()
	for _, i := range webhooksNeedingUpdate {
		webhookConfigCopy.GetWebhookClientCA(i).CABundle = bi.caBundle
	}
	_, err = bi.client.Update(ctx, webhookConfigCopy.GetObject(), metav1.UpdateOptions{})
	return err
}

func newMutatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().MutatingWebhookConfigurations()
	syncer := &webhookCABundleInjector[admissionregv1.MutatingWebhookConfiguration]{
		webhookConfigType:        "mutatingwebhookconfiguration",
		client:                   config.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		lister:                   informer.Lister(),
		newWebhookConfigAccessor: newMutatingWebhookAccessor,
		caBundle:                 config.caBundle,
	}
	return controllerConfig{
		name:               "MutatingWebhookCABundleInjector",
		sync:               syncer.Sync,
		informer:           informer.Informer(),
		annotationsChecker: annotationsChecker(api.InjectCABundleAnnotationName),
	}
}

func newValidatingWebhookInjectorConfig(config *caBundleInjectorConfig) controllerConfig {
	informer := config.kubeInformers.Admissionregistration().V1().ValidatingWebhookConfigurations()
	syncer := &webhookCABundleInjector[admissionregv1.ValidatingWebhookConfiguration]{
		webhookConfigType:        "validatingwebhookconfiguration",
		client:                   config.kubeClient.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		lister:                   informer.Lister(),
		newWebhookConfigAccessor: newValidatingWebhookAccessor,
		caBundle:                 config.caBundle,
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
