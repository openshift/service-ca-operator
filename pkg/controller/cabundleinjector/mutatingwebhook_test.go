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
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type webhookInjectTest interface {
	getWebhookName() string
	getCABundle() []byte
	injectorSetup(*testing.T, runtime.Object)
	sync() error
	validateAllCABundles(*testing.T, runtime.Object)
}

type mutatingInjectTest struct {
	injector    *mutatingWebhookCABundleInjector
	client      admissionregclient.MutatingWebhookConfigurationInterface
	syncContext factory.SyncContext
}

var _ webhookInjectTest = &mutatingInjectTest{}

func (m *mutatingInjectTest) getCABundle() []byte {
	return []byte("TESTCABUNDLE")
}

func (m *mutatingInjectTest) getWebhookName() string {
	return "test-mutating-webhook-configuration"
}

func (m *mutatingInjectTest) injectorSetup(t *testing.T, o runtime.Object) {
	clientObjects := []runtime.Object{} // objects to init the kubeclient with

	mwc, ok := o.(*admissionregv1.MutatingWebhookConfiguration)
	if !ok {
		t.Errorf("object is not of type MutatingWebhookConfiguration")
	}

	mutatingWebhookIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if mwc != nil {
		if err := mutatingWebhookIndexer.Add(mwc); err != nil {
			t.Fatal(err)
			clientObjects = append(clientObjects, mwc)
		}
	}
	lister := admissionreglister.NewMutatingWebhookConfigurationLister(mutatingWebhookIndexer)
	kubeclient := fake.NewSimpleClientset(clientObjects...)
	m.injector = &mutatingWebhookCABundleInjector{
		client:   kubeclient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
		lister:   lister,
		caBundle: m.getCABundle(),
	}
	m.client = kubeclient.AdmissionregistrationV1().MutatingWebhookConfigurations()
	m.syncContext = newTestSyncContext(mwc.Name)
}

func (m *mutatingInjectTest) sync() error {
	return m.injector.Sync(context.TODO(), m.syncContext)
}

func (m *mutatingInjectTest) validateAllCABundles(t *testing.T, o runtime.Object) {
	mwc, ok := o.(*admissionregv1.MutatingWebhookConfiguration)
	if !ok {
		t.Errorf("object is not of type MutatingWebhookConfiguration")
	}

	for _, webhook := range mwc.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, m.getCABundle()) {
			t.Errorf("expected %s, got %s", m.getCABundle(), webhook.ClientConfig.CABundle)
		}
	}
}

func TestMutatingWebhookCABundleInjectorSync(t *testing.T) {
	m := mutatingInjectTest{}

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

	mwc := &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: m.getWebhookName(),
			Annotations: map[string]string{
				api.InjectCABundleAnnotationName: "true",
			},
		},
		Webhooks: []admissionregv1.MutatingWebhook{
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

	m.injectorSetup(t, mwc)
	if _, err := m.client.Create(context.TODO(), mwc, metav1.CreateOptions{}); err != nil {
		t.Error(err)
	}

	if err := m.sync(); err != nil {
		t.Error(err)
	}

	mwc, err := m.client.Get(context.TODO(), m.getWebhookName(), metav1.GetOptions{})
	if err != nil {
		t.Error(err)
	}
	m.validateAllCABundles(t, mwc)
	mwc.Webhooks = append(mwc.Webhooks, admissionregv1.MutatingWebhook{
		Name:                    "ut-3.example.com",
		ClientConfig:            webhookClientConfig,
		SideEffects:             &sideEffectNone,
		AdmissionReviewVersions: []string{"v1"},
	})

	mwc, err = m.client.Update(context.TODO(), mwc, metav1.UpdateOptions{})
	if err != nil {
		t.Error(err)
	}

	m.injectorSetup(t, mwc)
	if _, err := m.client.Create(context.TODO(), mwc, metav1.CreateOptions{}); err != nil {
		t.Error(err)
	}

	if err := m.sync(); err != nil {
		t.Error(err)
	}

	mwc, err = m.client.Get(context.TODO(), m.getWebhookName(), metav1.GetOptions{})
	if err != nil {
		t.Error(err)
	}
	m.validateAllCABundles(t, mwc)
}

type testSyncContext struct {
	queueKey      string
	eventRecorder events.Recorder
}

func (c testSyncContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (c testSyncContext) QueueKey() string {
	return c.queueKey
}

func (c testSyncContext) Recorder() events.Recorder {
	return c.eventRecorder
}

func newTestSyncContext(queueKey string) factory.SyncContext {
	return testSyncContext{
		queueKey:      queueKey,
		eventRecorder: events.NewInMemoryRecorder("test"),
	}
}
