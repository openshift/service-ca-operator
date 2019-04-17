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

	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"math/big"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
)

const (
	serviceCAOperatorNamespace   = operatorclient.OperatorNamespace
	serviceCAOperatorPodPrefix   = operatorclient.OperatorNamespace // Same as operator namespace
	serviceCAControllerNamespace = operatorclient.TargetNamespace
	apiInjectorPodPrefix         = api.APIServiceInjectorDeploymentName
	configMapInjectorPodPrefix   = api.ConfigMapInjectorDeploymentName
	caControllerPodPrefix        = api.SignerControllerDeploymentName
	signingKeySecretName         = "service-serving-cert-signer-signing-key"
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

func pollForServiceServingSecretWithReturn(client *kubernetes.Clientset, secretName, namespace string) (*v1.Secret, error) {
	var secret *v1.Secret
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret = s
		return true, nil
	})
	return secret, err
}

func pollForCABundleInjectionConfigMapWithReturn(client *kubernetes.Clientset, configMapName, namespace string) (*v1.ConfigMap, error) {
	var configmap *v1.ConfigMap
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		configmap = cm
		return true, nil
	})
	return configmap, err
}

func pollForSecretChange(client *kubernetes.Clientset, secret *v1.Secret) error {
	return wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !bytes.Equal(s.Data[v1.TLSCertKey], secret.Data[v1.TLSCertKey]) &&
			!bytes.Equal(s.Data[v1.TLSPrivateKeyKey], secret.Data[v1.TLSPrivateKeyKey]) {
			return true, nil
		}
		return false, nil
	})
}

func pollForConfigMapChange(client *kubernetes.Clientset, compareConfigMap *v1.ConfigMap) error {
	return wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(compareConfigMap.Namespace).Get(compareConfigMap.Name, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, nil
		}
		if cm.Data[api.InjectionDataKey] != compareConfigMap.Data[api.InjectionDataKey] {
			// the change happened
			return true, nil
		}
		return false, nil
	})
}

func pollSecretForDataExist(client *kubernetes.Clientset, secret *v1.Secret, key string) error {
	return wait.PollImmediate(time.Second, 2*time.Minute, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return s.Data[key] != nil, nil
	})
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

	t.Run("refresh-CA", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}

		// create secret
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		secretCopy := secret.DeepCopy()

		// create configmap
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		configmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}
		configmapCopy := configmap.DeepCopy()
		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		// delete ca secret
		err = adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Delete(signingKeySecretName, nil)
		if err != nil {
			t.Fatalf("error deleting signing key: %v", err)
		}

		// make sure it's recreated
		err = pollForServiceServingSecret(adminClient, signingKeySecretName, serviceCAControllerNamespace)
		if err != nil {
			t.Fatalf("signing key was not recreated: %v", err)
		}

		err = pollForConfigMapChange(adminClient, configmapCopy)
		if err != nil {
			t.Fatalf("configmap bundle did not change: %v", err)
		}

		err = pollForSecretChange(adminClient, secretCopy)
		if err != nil {
			t.Fatalf("secret cert did not change: %v", err)
		}
	})

	t.Run("rotate-CA", func(t *testing.T) {
		ns, err := createTestNamespace(adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}

		// create secret
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		defer cleanupServiceSignerTestObjects(adminClient, testSecretName, testServiceName, ns.Name)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}

		secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		//secretCopy := secret.DeepCopy()

		// create configmap
		testConfigMapName := "test-configmap-" + randSeq(5)
		defer cleanupConfigMapCABundleInjectionTestObjects(adminClient, testConfigMapName, ns.Name)

		err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error creating annotated configmap: %v", err)
		}

		configmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}
		configmapCopy := configmap.DeepCopy()
		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}

		// Replace the CA secret with one that has passed its halfway-expired point, this way we force a rotation.
		//
		template := &x509.Certificate{
			Subject:            pkix.Name{CommonName: "test"},
			SignatureAlgorithm: x509.SHA256WithRSA,
			// A 4 hour cert that has 3 of those hours elapsed, more than halfway to expiration.
			NotBefore:             time.Now().Add(-3 * time.Hour),
			NotAfter:              time.Now().Add(1 * time.Hour),
			SerialNumber:          big.NewInt(1),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA: true,
		}
		priv, err := rsa.GenerateKey(rand2.Reader, 2048)
		if err != nil {
			t.Fatalf("error creating test CA key: %v", err)
		}
		caDer, err := x509.CreateCertificate(rand2.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			t.Fatalf("error creating test CA: %v", err)
		}
		certBuf := bytes.Buffer{}
		err = pem.Encode(&certBuf, &pem.Block{Type: cert.CertificateBlockType, Bytes: caDer})
		if err != nil {
			t.Fatalf("error encoding test CA pem: %v", err)
		}
		keyBuf := bytes.Buffer{}
		err = pem.Encode(&keyBuf, &pem.Block{Type: cert.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		if err != nil {
			t.Fatalf("error encoding test CA key: %v", err)
		}
		caSecret := &v1.Secret{
			Type: v1.SecretTypeTLS,
			ObjectMeta: metav1.ObjectMeta{
				Name:      signingKeySecretName,
				Namespace: serviceCAControllerNamespace,
			},
			Data: map[string][]byte{
				"tls.crt": certBuf.Bytes(),
				"tls.key": keyBuf.Bytes(),
			},
		}
		_, err = adminClient.CoreV1().Secrets(caSecret.Namespace).Update(caSecret)
		if err != nil {
			t.Fatalf("error updating secret with test CA: %v", err)
		}

		// Make sure secret is updated with ca-bundle.crt data containing 4 certs

		err = pollSecretForDataExist(adminClient, caSecret, "ca-bundle.crt")
		if err != nil {
			t.Fatalf("error confirming rotation of CA secret: %v", err)
		}
		// Make sure tls.crt is updated with two certs
		updatedCA, err := pollForServiceServingSecretWithReturn(adminClient, caSecret.Name, caSecret.Namespace)
		if err != nil {
			t.Fatalf("error fetching service CA secret: %v", err)
		}

		certs, err := cert.ParseCertsPEM(updatedCA.Data["tls.crt"])
		if err != nil {
			t.Fatalf("error parsing service CA after rotation: %v", err)
		}

		if len(certs) != 2 {
			t.Fatalf("service CA after rotation does not contain intermediate, contains %v certs", len(certs))
		}

		// Make sure a new signing cert gets renewed and contains the intermediate
		refreshedSecret, err := pollForServiceServingSecretWithReturn(adminClient, secret.Name, secret.Namespace)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret after rotation: %v", err)
		}

		refreshedParsedCerts, err := cert.ParseCertsPEM(refreshedSecret.Data["tls.crt"])
		if err != nil {
			t.Fatalf("error parsing service CA after rotation: %v", err)
		}

		if len(refreshedParsedCerts) != 2 {
			t.Fatalf("serving cert after rotation does not contain intermediate, contains %v certs", len(refreshedParsedCerts))
		}

		// Make sure configmap gets updated with full bundle 4 certs
		updatedConfigmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, configmapCopy.Name, configmapCopy.Namespace)
		if err != nil {
			t.Fatalf("error fetching ca bundle injection configmap: %v", err)
		}

		cmCerts, err := cert.ParseCertsPEM([]byte(updatedConfigmap.Data["ca-bundle.crt"]))
		if err != nil {
			t.Fatalf("error parsing configmap cert bundle after rotation: %v", err )
		}

		if len(cmCerts) != 4 {
			t.Fatalf("configmap bundle does not contain all CAs after rotation, contains %v certs", len(cmCerts))
		}

		// TODO: add some extra validation
	})

	// TODO: additional tests
	// - API service CA bundle injection
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
