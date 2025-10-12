package extended

import (
	"context"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	exutil "github.com/wangke19/origin-util"
)

var (
	oc                = exutil.NewCLI("sao-test", exutil.KubeConfigPath())
	operatorNamespace = "openshift-service-ca-operator"
	operandNamespace  = "openshift-service-ca"
)

var _ = g.Describe("[Jira:service-ca][sig-api-machinery] Service CA Operator", func() {
	defer g.GinkgoRecover()

	g.It("should have a running operator and managed resources", func() {
		exutil.By("checking for the service-ca-operator deployment")
		operatorDeployment, err := oc.AsAdmin().AdminKubeClient().AppsV1().Deployments(operatorNamespace).Get(context.Background(), "service-ca-operator", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(operatorDeployment.Status.AvailableReplicas).To(o.BeNumerically(">", 0))

		exutil.By("checking for the service-ca controller-manager deployment")
		var operandDeployment *appsv1.Deployment
		o.Eventually(func(g o.Gomega) {
			var err error
			operandDeployment, err = oc.AsAdmin().AdminKubeClient().AppsV1().Deployments(operandNamespace).Get(context.Background(), "service-ca", metav1.GetOptions{})
			g.Expect(err).NotTo(o.HaveOccurred())
		}).WithTimeout(1*time.Minute).WithPolling(5*time.Second).Should(o.Succeed())
		o.Expect(operandDeployment.Status.AvailableReplicas).To(o.BeNumerically(">", 0))

		exutil.By("checking for the signing-key secret")
		_, err = oc.AsAdmin().AdminKubeClient().CoreV1().Secrets(operandNamespace).Get(context.Background(), "signing-key", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("checking for the openshift-service-ca.crt configmap")
		_, err = oc.AsAdmin().AdminKubeClient().CoreV1().ConfigMaps(operandNamespace).Get(context.Background(), "openshift-service-ca.crt", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.It("should inject a CA bundle into an annotated configmap", func() {
		exutil.By("creating a new namespace for the test")
		testNamespace, err := oc.AsAdmin().AdminKubeClient().CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "service-ca-test-",
			},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			oc.AsAdmin().AdminKubeClient().CoreV1().Namespaces().Delete(context.Background(), testNamespace.Name, metav1.DeleteOptions{})
		}()

		exutil.By("creating a configmap with the inject-cabundle annotation")
		cmName := "test-cm"
		cm, err := oc.AsAdmin().AdminKubeClient().CoreV1().ConfigMaps(testNamespace.Name).Create(context.Background(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: cmName,
				Annotations: map[string]string{
					"service.beta.openshift.io/inject-cabundle": "true",
				},
			},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		exutil.By("waiting for the CA bundle to be injected")
		o.Eventually(func(g o.Gomega) {
			var pollErr error
			cm, pollErr = oc.AsAdmin().AdminKubeClient().CoreV1().ConfigMaps(testNamespace.Name).Get(context.Background(), cmName, metav1.GetOptions{})
			g.Expect(pollErr).NotTo(o.HaveOccurred())
			g.Expect(cm.Data).To(o.HaveKey("service-ca.crt"))
		}).WithTimeout(1*time.Minute).WithPolling(5*time.Second).Should(o.Succeed())

		exutil.By("verifying the injected CA bundle is not empty")
		o.Expect(cm.Data["service-ca.crt"]).NotTo(o.BeEmpty())
	})
})
