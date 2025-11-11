package test

import (
	"bytes"
	"context"
	"fmt"

	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	ote "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/openshift/service-ca-operator/test/tests-extension/util"
)

var (
	client     kubernetes.Interface
	config     *rest.Config
	promClient util.PrometheusClient
)

func init() {
	var err error
	client, err = util.GetKubeClient()
	if err != nil {
		panic(fmt.Sprintf("failed to get kube client: %v", err))
	}

	config, err = util.GetKubeConfig()
	if err != nil {
		panic(fmt.Sprintf("failed to get kube config: %v", err))
	}

	promClient, err = util.NewPrometheusClientForConfig(config)
	if err != nil {
		fmt.Printf("failed to get prometheus client: %v, skipping metrics tests", err)
		promClient = nil
	}
}

// setupServingCertTest creates namespace, service, and waits for cert secret
func setupServingCertTest(headless bool) (secretName, namespace string, cleanup func()) {
	secretName, serviceName, namespace := util.RandSeq(10), util.RandSeq(10), util.RandSeq(10)

	_, cleanup, err := util.CreateTestNamespace(client, namespace)
	o.Expect(err).NotTo(o.HaveOccurred())

	err = util.CreateServingCertAnnotatedService(client, secretName, serviceName, namespace, headless)
	o.Expect(err).NotTo(o.HaveOccurred())

	err = util.PollForServiceServingSecret(client, secretName, namespace)
	o.Expect(err).NotTo(o.HaveOccurred())

	return
}

// runServingCertTest runs test logic for both regular and headless services
func runServingCertTest(testFn func(secretName, namespace string)) {
	for _, headless := range []bool{false, true} {
		secretName, namespace, cleanup := setupServingCertTest(headless)
		defer cleanup()
		testFn(secretName, namespace)
	}
}

// testCARotation performs CA rotation and waits for stabilization
func testCARotation(rotationType func(kubernetes.Interface, *rest.Config) error, rotationName string) {
	g.By(fmt.Sprintf("Performing %s CA rotation", rotationName))
	err := util.CheckCARotation(client, config, rotationType)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Waiting for kube-apiserver to stabilize after CA rotation (max 20 min)")
	err = util.WaitForClusterOperatorHealthy(config, 20, "kube-apiserver")
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Verifying service-ca-operator remained healthy during rotation")
	err = util.CheckComponents(client)
	o.Expect(err).NotTo(o.HaveOccurred())
}

// webhookCleanup creates cleanup function for webhook resources
func webhookCleanup(client interface{}, name string) func() {
	return func() {
		if deleteClient, ok := client.(interface {
			Delete(context.Context, string, metav1.DeleteOptions) error
		}); ok {
			if err := deleteClient.Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
				fmt.Printf("Failed to cleanup resource %s: %v\n", name, err)
			}
		}
	}
}

// pollWebhookAndVerifyHealth polls webhook for CA injection and verifies cluster health
func pollWebhookAndVerifyHealth(webhookType string, pollFn func() error) {
	g.By(fmt.Sprintf("Polling %s for CA bundle injection (20 min timeout)", webhookType))
	err := pollFn()
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By(fmt.Sprintf("Verifying cluster health after %s injection", webhookType))
	err = util.CheckClusterOperatorsHealthy(client)
	o.Expect(err).NotTo(o.HaveOccurred())
}

// For new tests, use ote.Informing() decorator to mark as non-blocking in CI.
// Tests run in CI and collect data in Sippy, but don't block on failure.
// Remove Informing() decorator once the test proves stable (>95% pass rate in Sippy).
var _ = g.Describe("Service CA Operator", func() {
	g.BeforeEach(func() {
		err := util.CheckComponents(client)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should create a serving cert secret for services with the serving-cert annotation", ote.Informing(), g.Label("conformance", "serial"), func() {
		runServingCertTest(func(secretName, namespace string) {
			_, ok, err := util.CheckServiceServingCertSecretData(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(ok).To(o.BeTrue())
		})
	})

	g.It("should recreate a serving cert secret when the secret is deleted", ote.Informing(), g.Label("conformance", "serial"), func() {
		runServingCertTest(func(secretName, namespace string) {
			err := client.CoreV1().Secrets(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
			o.Expect(err).NotTo(o.HaveOccurred())

			err = util.PollForServiceServingSecret(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())
		})
	})

	g.It("should inject a CA bundle into an annotated configmap", ote.Informing(), g.Label("conformance", "parallel"), func() {
		configMapName, namespace := util.RandSeq(10), util.RandSeq(10)
		_, cleanup, err := util.CreateTestNamespace(client, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cleanup()

		err = util.CreateAnnotatedCABundleInjectionConfigMap(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = util.PollForConfigMapCAInjection(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = util.CheckConfigMapCABundleInjectionData(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should update CA bundle injection configmap when modified", ote.Informing(), g.Label("conformance", "parallel"), func() {
		configMapName, namespace := util.RandSeq(10), util.RandSeq(10)
		_, cleanup, err := util.CreateTestNamespace(client, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cleanup()

		err = util.CreateAnnotatedCABundleInjectionConfigMap(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = util.PollForConfigMapCAInjection(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = util.EditConfigMapCABundleInjectionData(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())

		err = util.PollForConfigMapCAInjection(client, configMapName, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should handle vulnerable legacy CA bundle injection configmap", ote.Informing(), g.Label("conformance", "parallel"), func() {
		namespace := util.RandSeq(10)
		_, cleanup, err := util.CreateTestNamespace(client, namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer cleanup()
	})

	g.It("should collect metrics and service CA metrics", ote.Informing(), g.Label("conformance", "parallel"), func() {
		if promClient == nil {
			g.Skip("skipping metrics test due to unavailable prometheus client")
		}
		// Test general metrics collection
		err := util.CheckMetricsCollection(promClient, "openshift-service-ca-operator")
		o.Expect(err).NotTo(o.HaveOccurred())

		// Test specific service CA metrics
		err = util.CheckServiceCAMetrics(client, promClient)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	// conformance/serial
	g.It("should refresh CA when secret is deleted", ote.Informing(), g.Label("conformance", "serial"), func() {
		err := util.PollForCARecreation(client)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should regenerate serving cert secret when TLS cert is modified", ote.Informing(), g.Label("conformance", "serial"), func() {
		runServingCertTest(func(secretName, namespace string) {
			originalBytes, _, err := util.CheckServiceServingCertSecretData(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = util.EditServingSecretData(client, secretName, namespace, "tls.crt")
			o.Expect(err).NotTo(o.HaveOccurred())

			updatedBytes, is509, err := util.CheckServiceServingCertSecretData(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(bytes.Equal(originalBytes, updatedBytes)).To(o.BeFalse())
			o.Expect(is509).To(o.BeTrue())
		})
	})

	g.It("should remove extra data from serving cert secret", ote.Informing(), g.Label("conformance", "serial"), func() {
		runServingCertTest(func(secretName, namespace string) {
			originalBytes, _, err := util.CheckServiceServingCertSecretData(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())

			err = util.EditServingSecretData(client, secretName, namespace, "foo")
			o.Expect(err).NotTo(o.HaveOccurred())

			updatedBytes, _, err := util.CheckServiceServingCertSecretData(client, secretName, namespace)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(bytes.Equal(originalBytes, updatedBytes)).To(o.BeTrue())
		})
	})

	g.It("should handle time-based CA rotation", ote.Informing(), g.Label("conformance", "serial"), func() {
		testCARotation(util.TriggerTimeBasedRotation, "time-based")
	})

	g.It("should handle forced CA rotation", ote.Informing(), g.Label("conformance", "serial"), func() {
		testCARotation(util.TriggerForcedRotation, "forced")
	})
})

// This test is SERIAL because it:
// 1. Requires a stable, healthy kube-apiserver (includes pre-checks)
// 2. May trigger kube-apiserver restarts during webhook CA injection
// 3. Tests cluster-wide webhook resources (APIService, CRD, webhooks)
// 4. Should run AFTER CA rotation tests have completed and cluster has stabilized
var _ = g.Describe("Service CA Operator Webhook Injection", ote.Informing(), g.Label("conformance", "serial"), func() {
	g.BeforeEach(func() {
		err := util.CheckComponents(client)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should inject CA bundle into all webhook types", func() {
		// Optimization: Create all webhook resources first, then poll all at once
		// This triggers kube-apiserver restart only once instead of 4 times

		// Pre-flight cluster health check (flake detection)
		g.By("Checking cluster operator status before webhook injection (flake detection)")
		if err := util.CheckClusterOperatorStatus(config, "kube-apiserver", "service-ca"); err != nil {
			g.Skip(fmt.Sprintf("Skipping webhook injection test: cluster environment is unhealthy before test execution (flake): %v", err))
		}
		g.By("Cluster operators are healthy, proceeding with webhook injection")

		expectedCABundle, err := util.PollForSigningCABundle(client)
		o.Expect(err).NotTo(o.HaveOccurred())

		// Create all webhook resources
		apiServiceClient := apiserviceclient.NewForConfigOrDie(config).ApiregistrationV1().APIServices()
		apiServiceObj, err := util.CreateAPIService(apiServiceClient, fmt.Sprintf("e2e-%s", util.RandSeq(10)), "v1alpha1")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer webhookCleanup(apiServiceClient, apiServiceObj.Name)()

		crdClient := apiextclient.NewForConfigOrDie(config).CustomResourceDefinitions()
		crdObj, err := util.CreateCRD(crdClient, fmt.Sprintf("e2e-%s.example.com", util.RandSeq(10)), "cabundleinjectiontargets", "v1beta1")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer webhookCleanup(crdClient, crdObj.Name)()

		mutatingWebhookClient := client.AdmissionregistrationV1().MutatingWebhookConfigurations()
		mutatingObj, err := util.CreateMutatingWebhookConfiguration(mutatingWebhookClient)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer webhookCleanup(mutatingWebhookClient, mutatingObj.Name)()

		validatingWebhookClient := client.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		validatingObj, err := util.CreateValidatingWebhookConfiguration(validatingWebhookClient)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer webhookCleanup(validatingWebhookClient, validatingObj.Name)()

		// Poll each webhook sequentially and verify cluster health after each
		pollWebhookAndVerifyHealth("APIService", func() error {
			_, err := util.PollForAPIServiceWithTimeout(apiServiceClient, apiServiceObj.Name, expectedCABundle, 20)
			return err
		})

		pollWebhookAndVerifyHealth("CRD", func() error {
			_, err := util.PollForCRDWithTimeout(crdClient, crdObj.Name, expectedCABundle, 20)
			return err
		})

		pollWebhookAndVerifyHealth("MutatingWebhookConfiguration", func() error {
			_, err := util.PollForMutatingWebhookConfigurationWithTimeout(mutatingWebhookClient, mutatingObj.Name, expectedCABundle, 20)
			return err
		})

		pollWebhookAndVerifyHealth("ValidatingWebhookConfiguration", func() error {
			_, err := util.PollForValidatingWebhookConfigurationWithTimeout(validatingWebhookClient, validatingObj.Name, expectedCABundle, 20)
			return err
		})
	})
})
