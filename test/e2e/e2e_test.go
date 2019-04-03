package e2e

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	serviceCAOperatorNamespace   = operatorclient.OperatorNamespace
	serviceCAOperatorPodPrefix   = operatorclient.OperatorNamespace // Same as operator namespace
	serviceCAControllerNamespace = operatorclient.TargetNamespace
	apiInjectorPodPrefix         = api.APIServiceInjectorDeploymentName
	configMapInjectorPodPrefix   = api.ConfigMapInjectorDeploymentName
	caControllerPodPrefix        = api.SignerControllerDeploymentName
)

func hasPodWithPrefixName(client *kubernetes.Clientset, name, namespace string) bool {
	if client == nil || len(name) == 0 || len(namespace) == 0 {
		return false
	}
	pods, err := client.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		return false
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.GetName(), name) {
			return true
		}
	}
	return false
}

func createTestNamespace(client *kubernetes.Clientset, namespaceName string) (*v1.Namespace, error) {
	ns, err := client.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	})
	return ns, err
}

// on success returns serviceName, secretName, nil
func createServingCertAnnotatedService(client *kubernetes.Clientset, secretName, serviceName, namespace string) error {
	_, err := client.CoreV1().Services(namespace).Create(&v1.Service{
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
	})
	return err
}

func createAnnotatedCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	_, err := client.CoreV1().ConfigMaps(namespace).Create(&v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
			Annotations: map[string]string{
				api.InjectCABundleAnnotationName: "true",
			},
		},
	})
	return err
}

func pollForServiceServingSecret(client *kubernetes.Clientset, secretName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func pollForCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func editServiceServingSecretData(client *kubernetes.Clientset, secretName, namespace, edit string) error {
	sss, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	scopy := sss.DeepCopy()
	switch edit {
	case "badCert":
		scopy.Data[v1.TLSCertKey] = []byte("blah")
	case "extraData":
		scopy.Data["foo"] = []byte("blah")
	}
	_, err = client.CoreV1().Secrets(namespace).Update(scopy)
	if err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	return nil
}

func editConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cmcopy := cm.DeepCopy()
	if len(cmcopy.Data) != 1 {
		return fmt.Errorf("ca bundle injection configmap missing data")
	}
	cmcopy.Data["foo"] = "blah"
	_, err = client.CoreV1().ConfigMaps(namespace).Update(cmcopy)
	if err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	return nil
}

func checkServiceServingCertSecretData(client *kubernetes.Clientset, secretName, namespace string) ([]byte, bool, error) {
	sss, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}
	if len(sss.Data) != 2 {
		return nil, false, fmt.Errorf("unexpected service serving secret data map length: %v", len(sss.Data))
	}
	ok := true
	_, ok = sss.Data[v1.TLSCertKey]
	_, ok = sss.Data[v1.TLSPrivateKeyKey]
	if !ok {
		return nil, false, fmt.Errorf("unexpected service serving secret data: %v", sss.Data)
	}
	block, _ := pem.Decode([]byte(sss.Data[v1.TLSCertKey]))
	if block == nil {
		return nil, false, fmt.Errorf("unable to decode TLSCertKey bytes")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return sss.Data[v1.TLSCertKey], false, nil
	}
	return sss.Data[v1.TLSCertKey], true, nil
}

func checkConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if len(cm.Data) != 1 {
		return fmt.Errorf("unexpected ca bundle injection configmap data map length: %v", len(cm.Data))
	}
	ok := true
	_, ok = cm.Data[api.InjectionDataKey]
	if !ok {
		return fmt.Errorf("unexpected ca bundle injection configmap data: %v", cm.Data)
	}
	return nil
}

func cleanupServiceSignerTestObjects(client *kubernetes.Clientset, secretName, serviceName, namespace string) {
	client.CoreV1().Secrets(namespace).Delete(secretName, &metav1.DeleteOptions{})
	client.CoreV1().Services(namespace).Delete(serviceName, &metav1.DeleteOptions{})
	client.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
	// TODO this should just delete the namespace and wait for it to be gone
	// it should probably fail the test if the namespace gets stuck
}

func cleanupConfigMapCABundleInjectionTestObjects(client *kubernetes.Clientset, cmName, namespace string) {
	client.CoreV1().ConfigMaps(namespace).Delete(cmName, &metav1.DeleteOptions{})
	client.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
	// TODO this should just delete the namespace and wait for it to be gone
	// it should probably fail the test if the namespace gets stuck
}

func TestE2E(t *testing.T) {
	// use /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	// load client
	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		t.Fatalf("error loading config: %v", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error loading admin config: %v", err)
	}
	adminClient, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error getting admin client: %v", err)
	}

	// the service-serving-cert-operator and controllers should be running as a stock OpenShift component. our first test is to
	// verify that all of the components are running.
	if !hasPodWithPrefixName(adminClient, serviceCAOperatorPodPrefix, serviceCAOperatorNamespace) {
		t.Fatalf("%s not running in %s namespace", serviceCAOperatorPodPrefix, serviceCAOperatorNamespace)
	}
	if !hasPodWithPrefixName(adminClient, apiInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", apiInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, configMapInjectorPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", configMapInjectorPodPrefix, serviceCAControllerNamespace)
	}
	if !hasPodWithPrefixName(adminClient, caControllerPodPrefix, serviceCAControllerNamespace) {
		t.Fatalf("%s not running in %s namespace", caControllerPodPrefix, serviceCAControllerNamespace)
	}

	// test the main feature. annotate service -> created secret
	t.Run("serving-cert-annotation", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
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
	})

	// test modified data in serving-cert-secret will regenerated
	t.Run("serving-cert-secret-modify-bad-tlsCert", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)
		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}

		err = editServiceServingSecretData(adminClient, testSecretName, ns.Name, "badCert")
		if err != nil {
			t.Fatalf("error editing serving cert secret: %v", err)
		}
		updatedBytes, is509, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}
		if bytes.Equal(originalBytes, updatedBytes) {
			t.Fatalf("expected TLSCertKey to be replaced with valid pem bytes")
		}
		if !is509 {
			t.Fatalf("TLSCertKey not valid pem bytes")
		}
	})

	// test extra data in serving-cert-secret will be removed
	t.Run("serving-cert-secret-add-data", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)
		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}

		err = editServiceServingSecretData(adminClient, testSecretName, ns.Name, "extraData")
		if err != nil {
			t.Fatalf("error editing serving cert secret: %v", err)
		}
		updatedBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking serving cert secret: %v", err)
		}
		if !bytes.Equal(originalBytes, updatedBytes) {
			t.Fatalf("did not expect TLSCertKey to be replaced with a new cert")
		}
	})

	// test ca bundle injection configmap
	t.Run("ca-bundle-injection-configmap", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}
	})

	// test updated data in ca bundle injection configmap will be stomped on
	t.Run("ca-bundle-injection-configmap-update", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		err = editConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error editing ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

	})

	// TODO: additional tests
	// - API service CA bundle injection
	// - regenerate serving cert
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var characters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

// TODO drop this and just use generate name
// used for random suffix
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}
