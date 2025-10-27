package test

import (
	"context"
	"os"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	operatorNamespace = "openshift-service-ca-operator"
	operandNamespace  = "openshift-service-ca"
)

// getKubeClient returns a Kubernetes client
func getKubeClient() (kubernetes.Interface, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// getKubeConfig returns Kubernetes configuration, preferring kubeconfig over in-cluster config
func getKubeConfig() (*rest.Config, error) {
	// First try to use kubeconfig file
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err == nil {
			return config, nil
		}
	}

	// Fall back to in-cluster config
	return rest.InClusterConfig()
}

var _ = g.Describe("[Jira:service-ca][sig-api-machinery] Service CA Operator", func() {
	defer g.GinkgoRecover()

	g.It("should have a running operator and managed resources [Suite:openshift/service-ca-operator/conformance/parallel]", func() {
		client, err := getKubeClient()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("checking for the service-ca-operator deployment")
		var operatorDeployment *appsv1.Deployment
		o.Eventually(func(gomega o.Gomega) {
			var err error
			operatorDeployment, err = client.AppsV1().Deployments(operatorNamespace).Get(context.Background(), "service-ca-operator", metav1.GetOptions{})
			gomega.Expect(err).NotTo(o.HaveOccurred())
			gomega.Expect(operatorDeployment.Status.AvailableReplicas).To(o.BeNumerically(">", 0))
		}).WithTimeout(1 * time.Minute).WithPolling(5 * time.Second).Should(o.Succeed())

		g.By("checking for the service-ca controller-manager deployment")
		var operandDeployment *appsv1.Deployment
		o.Eventually(func(gomega o.Gomega) {
			var err error
			operandDeployment, err = client.AppsV1().Deployments(operandNamespace).Get(context.Background(), "service-ca", metav1.GetOptions{})
			gomega.Expect(err).NotTo(o.HaveOccurred())
			gomega.Expect(operandDeployment.Status.AvailableReplicas).To(o.BeNumerically(">", 0))
		}).WithTimeout(1 * time.Minute).WithPolling(5 * time.Second).Should(o.Succeed())

		g.By("checking for the signing-key secret")
		o.Eventually(func(gomega o.Gomega) {
			_, err := client.CoreV1().Secrets(operandNamespace).Get(context.Background(), "signing-key", metav1.GetOptions{})
			gomega.Expect(err).NotTo(o.HaveOccurred())
		}).WithTimeout(1 * time.Minute).WithPolling(5 * time.Second).Should(o.Succeed())

		g.By("checking for the openshift-service-ca.crt configmap")
		o.Eventually(func(gomega o.Gomega) {
			_, err := client.CoreV1().ConfigMaps(operandNamespace).Get(context.Background(), "openshift-service-ca.crt", metav1.GetOptions{})
			gomega.Expect(err).NotTo(o.HaveOccurred())
		}).WithTimeout(1 * time.Minute).WithPolling(5 * time.Second).Should(o.Succeed())
	})

	g.It("should inject a CA bundle into an annotated configmap [Suite:openshift/service-ca-operator/conformance/parallel]", func() {
		client, err := getKubeClient()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("creating a new namespace for the test")
		testNamespace, err := client.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "service-ca-test-",
			},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			client.CoreV1().Namespaces().Delete(context.Background(), testNamespace.Name, metav1.DeleteOptions{})
		}()

		g.By("creating a configmap with the inject-cabundle annotation")
		cmName := "test-cm"
		cm, err := client.CoreV1().ConfigMaps(testNamespace.Name).Create(context.Background(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: cmName,
				Annotations: map[string]string{
					"service.beta.openshift.io/inject-cabundle": "true",
				},
			},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("waiting for the CA bundle to be injected")
		o.Eventually(func(gomega o.Gomega) {
			var pollErr error
			cm, pollErr = client.CoreV1().ConfigMaps(testNamespace.Name).Get(context.Background(), cmName, metav1.GetOptions{})
			gomega.Expect(pollErr).NotTo(o.HaveOccurred())
			gomega.Expect(cm.Data).To(o.HaveKey("service-ca.crt"))
		}).WithTimeout(1 * time.Minute).WithPolling(5 * time.Second).Should(o.Succeed())

		g.By("verifying the injected CA bundle is not empty")
		o.Expect(cm.Data["service-ca.crt"]).NotTo(o.BeEmpty())
	})
})
