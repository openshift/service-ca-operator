package cabundleinjector

import (
	"bytes"
	"context"
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	admissionreglister "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type validatingInjectTest struct {
	injector    *validatingWebhookCABundleInjector
	client      admissionregclient.ValidatingWebhookConfigurationInterface
	syncContext factory.SyncContext
}

var _ webhookInjectTest = &validatingInjectTest{}

func (v *validatingInjectTest) getCABundle() []byte {
	return []byte("TESTCABUNDLE")
}

func (v *validatingInjectTest) getWebhookName() string {
	return "test-validating-webhook-configuration"
}

func (v *validatingInjectTest) injectorSetup(t *testing.T, o runtime.Object) {
	clientObjects := []runtime.Object{} // objects to init the kubeclient with

	vwc, ok := o.(*admissionregv1.ValidatingWebhookConfiguration)
	if !ok {
		t.Errorf("object is not of type ValidatingWebhookConfiguration")
	}

	validatingWebhookIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if vwc != nil {
		if err := validatingWebhookIndexer.Add(vwc); err != nil {
			t.Fatal(err)
			clientObjects = append(clientObjects, vwc)
		}
	}
	lister := admissionreglister.NewValidatingWebhookConfigurationLister(validatingWebhookIndexer)
	kubeclient := fake.NewSimpleClientset(clientObjects...)
	v.injector = &validatingWebhookCABundleInjector{
		client:   kubeclient.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
		lister:   lister,
		caBundle: v.getCABundle(),
	}
	v.client = kubeclient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	v.syncContext = newTestSyncContext(vwc.Name)
}

func (v *validatingInjectTest) sync() error {
	return v.injector.Sync(context.TODO(), v.syncContext)
}

func (v *validatingInjectTest) validateAllCABundles(t *testing.T, o runtime.Object) {
	vwc, ok := o.(*admissionregv1.ValidatingWebhookConfiguration)
	if !ok {
		t.Errorf("object is not of type ValidatingWebhookConfiguration")
	}

	for _, webhook := range vwc.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, v.getCABundle()) {
			t.Errorf("expected %s, got %s", v.getCABundle(), webhook.ClientConfig.CABundle)
		}
	}
}

func TestValidatingWebhookCABundleInjectorSync(t *testing.T) {
	m := validatingInjectTest{}

	// Common webhook config
	webhookClientConfig := admissionregv1.WebhookClientConfig{
		// A service must be specified for validation to
		// accept a cabundle.
		Service: &admissionregv1.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
	sideEffectNone := admissionregv1.SideEffectClassNone

	vwc := &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: m.getWebhookName(),
			Annotations: map[string]string{
				api.InjectCABundleAnnotationName: "true",
			},
		},
		Webhooks: []admissionregv1.ValidatingWebhook{
			// Specify 2 webhooks to ensure more than 1 webhook will be updated
			{
				Name:                    "ut-1.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
			{
				Name:                    "ut-2.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	m.injectorSetup(t, vwc)
	if _, err := m.client.Create(context.TODO(), vwc, metav1.CreateOptions{}); err != nil {
		t.Error(err)
	}

	if err := m.sync(); err != nil {
		t.Error(err)
	}

	vwc, err := m.client.Get(context.TODO(), m.getWebhookName(), metav1.GetOptions{})
	if err != nil {
		t.Error(err)
	}
	m.validateAllCABundles(t, vwc)
	vwc.Webhooks = append(vwc.Webhooks, admissionregv1.ValidatingWebhook{
		Name:                    "ut-3.example.com",
		ClientConfig:            webhookClientConfig,
		SideEffects:             &sideEffectNone,
		AdmissionReviewVersions: []string{"v1"},
	})

	vwc, err = m.client.Update(context.TODO(), vwc, metav1.UpdateOptions{})
	if err != nil {
		t.Error(err)
	}

	m.injectorSetup(t, vwc)
	if _, err := m.client.Create(context.TODO(), vwc, metav1.CreateOptions{}); err != nil {
		t.Error(err)
	}

	if err := m.sync(); err != nil {
		t.Error(err)
	}

	vwc, err = m.client.Get(context.TODO(), m.getWebhookName(), metav1.GetOptions{})
	if err != nil {
		t.Error(err)
	}
	m.validateAllCABundles(t, vwc)
}
