package e2e

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

const (
	pollInterval = 5 * time.Second
	pollTimeout  = 60 * time.Second
)

var characters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

func init() {
	rand.Seed(time.Now().UnixNano())
}

var _ = g.Describe("[sig-service-ca] service-ca-operator", func() {
	g.Context("serving-cert-annotation", func() {
		for _, headless := range []bool{false, true} {
			g.It(fmt.Sprintf("[Operator][Serial] should provision certificates for services with headless=%v", headless), func() {
				testServingCertAnnotation(g.GinkgoTB(), headless)
			})
		}
	})
})

// testServingCertAnnotation checks that services with the serving-cert annotation
// get TLS certificates automatically provisioned.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests and Ginkgo tests.
//
// This situation is temporary until we test the new e2e jobs with OTE.
// Eventually all tests will be run only as part of the OTE framework.
func testServingCertAnnotation(t testing.TB, headless bool) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)

	err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, headless)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}

	err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}

	_, is509, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking serving cert secret: %v", err)
	}
	if !is509 {
		t.Fatalf("TLSCertKey not valid pem bytes")
	}
}

// getKubeClient returns a Kubernetes client for e2e tests.
// It uses /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env.
func getKubeClient() (*kubernetes.Clientset, error) {
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	return getKubeClientFromPath(confPath)
}

// getKubeClientFromPath returns a Kubernetes client from the given kubeconfig path.
func getKubeClientFromPath(confPath string) (*kubernetes.Clientset, error) {
	// Use BuildConfigFromFlags to avoid stdout output that interferes with OTE JSON parsing
	config, err := clientcmd.BuildConfigFromFlags("", confPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}

	adminClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %w", err)
	}
	return adminClient, nil
}

// createTestNamespace creates a namespace and returns a cleanup function.
func createTestNamespace(t testing.TB, client *kubernetes.Clientset, namespaceName string) (*v1.Namespace, func(), error) {
	ns, err := client.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}, metav1.CreateOptions{})
	cleanup := func() {
		if err := client.CoreV1().Namespaces().Delete(context.TODO(), ns.Name, metav1.DeleteOptions{}); err != nil {
			t.Logf("Deleting namespace %s failed: %v", ns.Name, err)
		}
	}
	return ns, cleanup, err
}

// createServingCertAnnotatedService creates a service with serving cert annotation.
func createServingCertAnnotatedService(client *kubernetes.Clientset, secretName, serviceName, namespace string, headless bool) error {
	const owningHeadlessServiceLabelName = "owning-headless-service"
	service := &v1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Annotations: map[string]string{
				api.ServingCertSecretAnnotation: secretName,
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name: "tests",
					Port: 8443,
				},
			},
		},
	}
	if headless {
		service.Spec.Selector = map[string]string{
			owningHeadlessServiceLabelName: serviceName,
		}
		service.Spec.ClusterIP = v1.ClusterIPNone
	}
	_, err := client.CoreV1().Services(namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	return err
}

// pollForServiceServingSecret polls until the serving cert secret exists.
func pollForServiceServingSecret(client *kubernetes.Clientset, secretName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// checkServiceServingCertSecretData verifies the secret contains valid TLS cert and key.
func checkServiceServingCertSecretData(client *kubernetes.Clientset, secretName, namespace string) ([]byte, bool, error) {
	sss, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}
	if len(sss.Data) != 2 {
		return nil, false, fmt.Errorf("unexpected service serving secret data map length: %v", len(sss.Data))
	}
	certBytes, ok := sss.Data[v1.TLSCertKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected service serving secret data: %v", sss.Data)
	}
	_, ok = sss.Data[v1.TLSPrivateKeyKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected service serving secret data: %v", sss.Data)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, false, fmt.Errorf("unable to decode TLSCertKey bytes")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certBytes, false, nil
	}
	return certBytes, true, nil
}

// randSeq generates a random string for test resource names.
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}
