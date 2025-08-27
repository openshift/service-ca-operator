package cabundleinjector

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

func TestWebhookCABundleInjectorSync(t *testing.T) {
	testCABundle := []byte("something")

	tests := []struct {
		name             string
		webhooks         []admissionregv1.ValidatingWebhook
		expectedWebhooks []admissionregv1.ValidatingWebhook
		wantErr          bool
	}{
		{
			name: "no webhooks",
		},
		{
			name: "single webhook to fill",
			webhooks: []admissionregv1.ValidatingWebhook{
				{
					ClientConfig: admissionregv1.WebhookClientConfig{},
				},
			},
			expectedWebhooks: []admissionregv1.ValidatingWebhook{
				{
					ClientConfig: admissionregv1.WebhookClientConfig{
						CABundle: testCABundle,
					},
				},
			},
		},
		{
			name: "multiple webhooks to fill",
			webhooks: []admissionregv1.ValidatingWebhook{
				{
					ClientConfig: admissionregv1.WebhookClientConfig{},
				},
				{
					ClientConfig: admissionregv1.WebhookClientConfig{
						CABundle: []byte("random other string"),
					},
				},
			},
			expectedWebhooks: []admissionregv1.ValidatingWebhook{
				{
					ClientConfig: admissionregv1.WebhookClientConfig{
						CABundle: testCABundle,
					},
				},
				{
					ClientConfig: admissionregv1.WebhookClientConfig{
						CABundle: testCABundle,
					},
				},
			},
		},
		{
			name: "conflicting annotations",
			webhooks: []admissionregv1.ValidatingWebhook{
				{
					ClientConfig: admissionregv1.WebhookClientConfig{},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWebhook := &admissionregv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhook",
					Annotations: map[string]string{
						api.InjectCABundleAnnotationName: "true",
					},
				},
				Webhooks: tt.webhooks,
			}
			if tt.name == "conflicting annotations" {
				testWebhook.ObjectMeta.Annotations["service.beta.openshift.io/inject-cabundle"] = "true"
				testWebhook.ObjectMeta.Labels = map[string]string{
					"config.openshift.io/inject-trusted-cabundle": "true",
				}
			}

			testCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			webhookClient := fake.NewSimpleClientset(testWebhook)
			webhookInformer := informers.NewSharedInformerFactory(webhookClient, 1*time.Hour)
			go webhookInformer.Start(testCtx.Done())
			waitSuccess := cache.WaitForCacheSync(testCtx.Done(), webhookInformer.Admissionregistration().V1().ValidatingWebhookConfigurations().Informer().HasSynced)
			require.True(t, waitSuccess)

			injector := webhookCABundleInjector[admissionregv1.ValidatingWebhookConfiguration]{
				webhookConfigType:        "testwebhook",
				newWebhookConfigAccessor: newValidatingWebhookAccessor,
				client:                   webhookClient.AdmissionregistrationV1().ValidatingWebhookConfigurations(),
				lister:                   webhookInformer.Admissionregistration().V1().ValidatingWebhookConfigurations().Lister(),
				caBundle:                 testCABundle,
			}

			if gotErr := injector.Sync(testCtx, testContext{"test-webhook"}); (gotErr != nil) != tt.wantErr {
				t.Errorf("webhookCABundleInjector.Sync() = %v, want %v", gotErr, tt.wantErr)
			}

			gotWebhook, err := webhookClient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(testCtx, "test-webhook", metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.expectedWebhooks, gotWebhook.Webhooks)
		})
	}
}

type testContext struct {
	key string
}

func (c testContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (c testContext) QueueKey() string {
	return c.key
}

func (c testContext) Recorder() events.Recorder {
	return nil
}
