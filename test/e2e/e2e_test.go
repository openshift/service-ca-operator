package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	admissionreg "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	"k8s.io/utils/pointer"

	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/test/library/metrics"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
	"github.com/openshift/service-ca-operator/test/util"
)

const (
	serviceCAOperatorNamespace   = operatorclient.OperatorNamespace
	serviceCAOperatorPodPrefix   = operatorclient.OperatorName
	serviceCAControllerNamespace = operatorclient.TargetNamespace
	serviceCAPodPrefix           = api.ServiceCADeploymentName
	signingKeySecretName         = api.ServiceCASecretName

	// A label used to attach StatefulSet pods to a headless service created by
	// createServingCertAnnotatedService
	owningHeadlessServiceLabelName = "owning-headless-service"

	pollInterval = 5 * time.Second
	pollTimeout  = 60 * time.Second

	// Rotation of all certs and bundles is expected to take a considerable amount of time
	// due to the operator having to restart each controller and then each controller having
	// to acquire the leader election lease and update all targeted resources.
	rotationTimeout = 5 * time.Minute
	// Polling for resources related to rotation may be delayed by the number of resources
	// that are updated in the cluster in response to rotation.
	rotationPollTimeout = 4 * time.Minute

	minimumTrustDuration       = time.Hour + 15*time.Minute
	signingCertificateLifetime = time.Hour*2 + 30*time.Minute
)

// checkComponents verifies that the components of the operator are running.
func checkComponents(t *testing.T, client *kubernetes.Clientset) {
	componentConfigs := []struct {
		namespace string
		podPrefix string
	}{
		{serviceCAOperatorNamespace, serviceCAOperatorPodPrefix},
		{serviceCAControllerNamespace, serviceCAPodPrefix},
	}
	for _, cfg := range componentConfigs {
		pods, err := client.CoreV1().Pods(cfg.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("Failed to list pods in namespace %q: %v", cfg.namespace, err)
		}
		podFound := false
		for _, pod := range pods.Items {
			if strings.HasPrefix(pod.GetName(), cfg.podPrefix) {
				podFound = true
				break
			}
		}
		if !podFound {
			t.Fatalf("No pods with prefix %q found running in namespace %q", cfg.podPrefix, cfg.namespace)
		}
	}
}

func createTestNamespace(t *testing.T, client *kubernetes.Clientset, namespaceName string) (*v1.Namespace, func(), error) {
	ns, err := client.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
		},
	}, metav1.CreateOptions{})
	cleanup := func() {
		if err := client.CoreV1().Namespaces().Delete(context.TODO(), ns.Name, metav1.DeleteOptions{}); err != nil {
			tlogf(t, "Deleting namespace %s failed: %v", ns.Name, err)
		}
	}
	return ns, cleanup, err
}

func createServingCertAnnotatedService(client *kubernetes.Clientset, secretName, serviceName, namespace string, headless bool) error {
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

func createStatefulSet(client *kubernetes.Clientset, secretName, statefulSetName, serviceName, namespace string, numReplicas int) error {
	const podLabelName = "pod-label"
	podLabelValue := statefulSetName + "-pod-label"
	replicasInt32 := int32(numReplicas)
	_, err := client.AppsV1().StatefulSets(namespace).Create(context.TODO(), &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: statefulSetName,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicasInt32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{podLabelName: podLabelValue},
			},
			ServiceName:         serviceName,
			PodManagementPolicy: appsv1.ParallelPodManagement, // We want changes to happen fast, there isn't really state to maintain.
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						podLabelName:                   podLabelValue,
						owningHeadlessServiceLabelName: serviceName,
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:  statefulSetName + "-container",
						Image: "nicolaka/netshoot:latest",
						Ports: []v1.ContainerPort{{
							ContainerPort: 8443,
						}},
						Command: []string{
							"/bin/sh",
							"-c",
							`openssl s_server -port 8443 -cert /srv/certificates/tls.crt -key /srv/certificates/tls.key -www`,
						},
						WorkingDir: "/",
						VolumeMounts: []v1.VolumeMount{{
							Name:      "serving-cert",
							MountPath: "/srv/certificates",
						}},
					}},
					Volumes: []v1.Volume{{
						Name: "serving-cert",
						VolumeSource: v1.VolumeSource{
							Secret: &v1.SecretVolumeSource{
								SecretName: secretName,
							},
						},
					}},
				},
			},
		},
	}, metav1.CreateOptions{})
	return err
}

func createAnnotatedCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	obj := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	_, err := client.CoreV1().ConfigMaps(namespace).Create(context.TODO(), obj, metav1.CreateOptions{})
	return err
}

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

func pollForCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func editServingSecretData(t *testing.T, client *kubernetes.Clientset, secretName, namespace, keyName string) error {
	sss, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	scopy := sss.DeepCopy()
	scopy.Data[keyName] = []byte("blah")
	_, err = client.CoreV1().Secrets(namespace).Update(context.TODO(), scopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return pollForSecretChange(t, client, scopy, keyName)
}

func editConfigMapCABundleInjectionData(t *testing.T, client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cmcopy := cm.DeepCopy()
	if len(cmcopy.Data) != 1 {
		return fmt.Errorf("ca bundle injection configmap missing data")
	}
	cmcopy.Data["foo"] = "blah"
	_, err = client.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cmcopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return pollForConfigMapChange(t, client, cmcopy, "foo")
}

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

func checkConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
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

func pollForConfigMapCAInjection(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if len(cm.Data) != 1 {
			return false, nil
		}
		_, ok := cm.Data[api.InjectionDataKey]
		if !ok {
			return false, nil
		}
		return true, nil
	})
}

func pollForServiceServingSecretWithReturn(client *kubernetes.Clientset, secretName, namespace string) (*v1.Secret, error) {
	var secret *v1.Secret
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
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
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
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

func pollForSecretChange(t *testing.T, client *kubernetes.Clientset, secret *v1.Secret, keysToChange ...string) error {
	return wait.PollImmediate(pollInterval, rotationPollTimeout, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "failed to get secret: %v", err)
			return false, nil
		}
		for _, key := range keysToChange {
			if bytes.Equal(s.Data[key], secret.Data[key]) {
				return false, nil
			}
		}
		return true, nil
	})
}

func pollForConfigMapChange(t *testing.T, client *kubernetes.Clientset, compareConfigMap *v1.ConfigMap, keysToChange ...string) error {
	return wait.PollImmediate(pollInterval, rotationPollTimeout, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(compareConfigMap.Namespace).Get(context.TODO(), compareConfigMap.Name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "failed to get configmap: %v", err)
			return false, nil
		}
		for _, key := range keysToChange {
			if cm.Data[key] == compareConfigMap.Data[key] {
				return false, nil
			}
		}
		return true, nil
	})
}

type triggerRotationFunc func(*testing.T, *kubernetes.Clientset, *rest.Config)

func checkCARotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config, triggerRotation triggerRotationFunc) {
	ns, cleanup, err := createTestNamespace(t, client, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	// Prompt the creation of service cert secrets
	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	testHeadlessServiceName := "test-headless-service-" + randSeq(5)
	testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

	err = createServingCertAnnotatedService(client, testSecretName, testServiceName, ns.Name, false)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	if err = createServingCertAnnotatedService(client, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
		t.Fatalf("error creating annotated headless service: %v", err)
	}

	// Prompt the injection of the ca bundle into a configmap
	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(client, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	// Retrieve the pre-rotation service cert
	oldCertPEM, oldKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	oldHeadlessCertPEM, oldHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the pre-rotation ca bundle
	oldBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationPollTimeout, nil)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Prompt CA rotation
	triggerRotation(t, client, config)

	// Retrieve the post-rotation service cert
	newCertPEM, newKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationTimeout, oldCertPEM, oldKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	newHeadlessCertPEM, newHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationTimeout, oldHeadlessCertPEM, oldHeadlessKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the post-rotation ca bundle
	newBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationTimeout, oldBundlePEM)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Determine the dns name valid for the serving cert
	certs, err := util.PemToCerts(newCertPEM)
	if err != nil {
		t.Fatalf("error decoding pem to certs: %v", err)
	}
	dnsName := certs[0].Subject.CommonName

	util.CheckRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)

	for i := 0; i < 3; i++ { // 3 is an arbitrary number of hostnames to try
		dnsName := fmt.Sprintf("some-statefulset-%d.%s.%s.svc", i, testHeadlessServiceName, ns.Name)
		util.CheckRotation(t, dnsName, oldHeadlessCertPEM, oldHeadlessKeyPEM, oldBundlePEM, newHeadlessCertPEM, newHeadlessKeyPEM, newBundlePEM)
	}
}

// triggerTimeBasedRotation replaces the current CA cert with one that
// is not valid for the minimum required duration and waits for the CA
// to be rotated.
func triggerTimeBasedRotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config) {
	// A rotation-prompting CA cert needs to be a renewed instance
	// (i.e. share the same public and private keys) of the current
	// cert to ensure that trust will be maintained for unrefreshed
	// clients and servers.

	// Retrieve current CA
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	currentCACerts, err := util.PemToCerts(secret.Data[v1.TLSCertKey])
	if err != nil {
		t.Fatalf("error unmarshaling %q: %v", v1.TLSCertKey, err)
	}
	currentCAKey, err := util.PemToKey(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("error unmarshalling %q: %v", v1.TLSPrivateKeyKey, err)
	}
	currentCAConfig := &crypto.TLSCertificateConfig{
		Certs: currentCACerts,
		Key:   currentCAKey,
	}

	// Trigger rotation by renewing the current ca with an expiry that
	// is sooner than the minimum required duration.
	renewedCAConfig, err := operator.RenewSelfSignedCertificate(currentCAConfig, 1*time.Hour, true)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}
	renewedCACertPEM, renewedCAKeyPEM, err := renewedCAConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding renewed ca to pem: %v", err)
	}

	// Write the renewed CA
	secret = &v1.Secret{
		Type: v1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      signingKeySecretName,
			Namespace: serviceCAControllerNamespace,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       renewedCACertPEM,
			v1.TLSPrivateKeyKey: renewedCAKeyPEM,
		},
	}
	_, _, err = resourceapply.ApplySecret(context.Background(), client.CoreV1(), events.NewInMemoryRecorder("test"), secret)
	if err != nil {
		t.Fatalf("error updating secret with test CA: %v", err)
	}

	_ = pollForCARotation(t, client, renewedCACertPEM, renewedCAKeyPEM)
}

// triggerForcedRotation forces the rotation of the current CA via the
// operator config.
func triggerForcedRotation(t *testing.T, client *kubernetes.Clientset, config *rest.Config) {
	// Retrieve the cert and key PEM of the current CA to be able to
	// detect when rotation has completed.
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	caCertPEM := secret.Data[v1.TLSCertKey]
	caKeyPEM := secret.Data[v1.TLSPrivateKeyKey]

	// Set a custom validity duration longer than the default to
	// validate that a custom expiry on rotation is possible.
	defaultDuration := signingCertificateLifetime
	customDuration := defaultDuration + 1*time.Hour

	// Trigger a forced rotation by updating the operator config
	// with a reason.
	forceUnsupportedServiceCAConfigRotation(t, config, secret, customDuration)

	signingSecret := pollForCARotation(t, client, caCertPEM, caKeyPEM)

	// Check that the expiry of the new CA is longer than the default
	rawCert := signingSecret.Data[v1.TLSCertKey]
	certs, err := cert.ParseCertsPEM(rawCert)
	if err != nil {
		t.Fatalf("Failed to parse signing secret cert: %v", err)
	}
	if !certs[0].NotAfter.After(time.Now().Add(defaultDuration)) {
		t.Fatalf("Custom validity duration was not used to generate the new CA")
	}
}

func forceUnsupportedServiceCAConfigRotation(t *testing.T, config *rest.Config, currentSigningKeySecret *v1.Secret, validityDuration time.Duration) {
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		t.Fatalf("error creating operator client: %v", err)
	}
	operatorConfig, err := operatorClient.OperatorV1().ServiceCAs().Get(context.TODO(), api.OperatorConfigInstanceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving operator config: %v", err)
	}
	var forceRotationReason string
	for i := 0; ; i++ {
		forceRotationReason = fmt.Sprintf("service-ca-e2e-force-rotation-reason-%d", i)
		if currentSigningKeySecret.Annotations[api.ForcedRotationReasonAnnotationName] != forceRotationReason {
			break
		}
	}
	rawUnsupportedServiceCAConfig, err := operator.RawUnsupportedServiceCAConfig(forceRotationReason, validityDuration)
	if err != nil {
		t.Fatalf("failed to create raw unsupported config overrides: %v", err)
	}
	operatorConfig.Spec.UnsupportedConfigOverrides.Raw = rawUnsupportedServiceCAConfig
	_, err = operatorClient.OperatorV1().ServiceCAs().Update(context.TODO(), operatorConfig, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating operator config: %v", err)
	}
}

// pollForCARotation polls for the signing secret to be changed in
// response to CA rotation.
func pollForCARotation(t *testing.T, client *kubernetes.Clientset, caCertPEM, caKeyPEM []byte) *v1.Secret {
	secret, err := pollForUpdatedSecret(t, client, serviceCAControllerNamespace, signingKeySecretName, rotationPollTimeout, map[string][]byte{
		v1.TLSCertKey:           caCertPEM,
		v1.TLSPrivateKeyKey:     caKeyPEM,
		api.BundleDataKey:       nil,
		api.IntermediateDataKey: nil,
	})
	if err != nil {
		t.Fatalf("error waiting for CA rotation: %v", err)
	}
	return secret
}

// pollForCARecreation polls for the signing secret to be re-created in
// response to CA secret deletion.
func pollForCARecreation(client *kubernetes.Clientset) error {
	return wait.PollImmediate(time.Second, rotationPollTimeout, func() (bool, error) {
		_, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// pollForUpdatedServingCert returns the cert and key PEM if it changes from
// that provided before the polling timeout.
func pollForUpdatedServingCert(t *testing.T, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldCertValue, oldKeyValue []byte) ([]byte, []byte, error) {
	secret, err := pollForUpdatedSecret(t, client, namespace, name, timeout, map[string][]byte{
		v1.TLSCertKey:       oldCertValue,
		v1.TLSPrivateKeyKey: oldKeyValue,
	})
	if err != nil {
		return nil, nil, err
	}
	return secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey], nil
}

// pollForUpdatedSecret returns the given secret if its data changes from
// that provided before the polling timeout.
func pollForUpdatedSecret(t *testing.T, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldData map[string][]byte) (*v1.Secret, error) {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", namespace, name)
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		err = util.CheckData(oldData, secret.Data)
		if err != nil {
			return nil, err
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*v1.Secret), nil
}

// pollForInjectedCABundle returns the bytes for the injection key in
// the targeted configmap if the value of the key changes from that
// provided before the polling timeout.
func pollForInjectedCABundle(t *testing.T, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, namespace, name, api.InjectionDataKey, timeout, oldValue)
}

// pollForSigningCABundle returns the bytes for the bundle key of the
// signing ca bundle configmap if the value is non-empty before the
// polling timeout.
func pollForSigningCABundle(t *testing.T, client *kubernetes.Clientset) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, serviceCAControllerNamespace, api.SigningCABundleConfigMapName, api.BundleDataKey, pollTimeout, nil)
}

// pollForUpdatedConfigMap returns the given configmap if its data changes from
// that provided before the polling timeout.
func pollForUpdatedConfigMap(t *testing.T, client *kubernetes.Clientset, namespace, name, key string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	resourceID := fmt.Sprintf("ConfigMap \"%s/%s\"", namespace, name)
	expectedDataSize := 1
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if len(configMap.Data) != expectedDataSize {
			return nil, fmt.Errorf("expected data size %d, got %d", expectedDataSize, len(configMap.Data))
		}
		value, ok := configMap.Data[key]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", key)
		}
		if value == string(oldValue) {
			return nil, fmt.Errorf("value for key %q has not changed", key)
		}
		return configMap, nil
	})
	if err != nil {
		return nil, err
	}
	configMap := obj.(*v1.ConfigMap)
	return []byte(configMap.Data[key]), nil
}

// pollForAPIService returns the specified APIService if its ca bundle
// matches the provided value before the polling timeout.
func pollForAPIService(t *testing.T, client apiserviceclientv1.APIServiceInterface, name string, expectedCABundle []byte) (*apiregv1.APIService, error) {
	resourceID := fmt.Sprintf("APIService %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		apiService, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		actualCABundle := apiService.Spec.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does match the expected value")
		}
		return apiService, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiregv1.APIService), nil
}

// pollForCRD returns the specified CustomResourceDefinition if the ca
// bundle for its conversion webhook config matches the provided value
// before the polling timeout.
func pollForCRD(t *testing.T, client apiextclient.CustomResourceDefinitionInterface, name string, expectedCABundle []byte) (*apiext.CustomResourceDefinition, error) {
	resourceID := fmt.Sprintf("CustomResourceDefinition %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		crd, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if crd.Spec.Conversion == nil || crd.Spec.Conversion.Webhook == nil || crd.Spec.Conversion.Webhook.ClientConfig == nil {
			return nil, fmt.Errorf("spec.conversion.webhook.webhook.clientConfig not set")
		}
		actualCABundle := crd.Spec.Conversion.Webhook.ClientConfig.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does match the expected value")
		}
		return crd, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiext.CustomResourceDefinition), nil
}

// pollForMutatingWebhookConfiguration returns the specified
// MutatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForMutatingWebhookConfiguration(t *testing.T, client admissionregclient.MutatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.MutatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("MutatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.MutatingWebhookConfiguration), nil
}

// pollForValidatingWebhookConfiguration returns the specified
// ValidatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForValidatingWebhookConfiguration(t *testing.T, client admissionregclient.ValidatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.ValidatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("ValidatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.ValidatingWebhookConfiguration), nil
}

// checkWebhookCABundle checks that the ca bundle for the named webhook matches
// the expected value.
func checkWebhookCABundle(webhookName string, expectedCABundle, actualCABundle []byte) error {
	if len(actualCABundle) == 0 {
		return fmt.Errorf("ca bundle not injected for webhook %q", webhookName)
	}
	if !bytes.Equal(actualCABundle, expectedCABundle) {
		return fmt.Errorf("ca bundle does match the expected value for webhook %q", webhookName)
	}
	return nil
}

// setInjectionAnnotation sets the annotation that will trigger the
// injection of a ca bundle.
func setInjectionAnnotation(objMeta *metav1.ObjectMeta) {
	if objMeta.Annotations == nil {
		objMeta.Annotations = map[string]string{}
	}
	objMeta.Annotations[api.InjectCABundleAnnotationName] = "true"
}

// pollForResource returns a kruntime.Object if the accessor returns without error before the timeout.
func pollForResource(t *testing.T, resourceID string, timeout time.Duration, accessor func() (kruntime.Object, error)) (kruntime.Object, error) {
	var obj kruntime.Object
	err := wait.PollImmediate(pollInterval, timeout, func() (bool, error) {
		o, err := accessor()
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			tlogf(t, "an error occurred while polling for %s: %v", resourceID, err)
			return false, nil
		}
		obj = o
		return true, nil
	})
	return obj, err
}

func tlogf(t *testing.T, fmt string, args ...interface{}) {
	t.Logf("%s: "+fmt, time.Now().Format(time.RFC1123Z), args)
}

func checkClientPodRcvdUpdatedServerCert(t *testing.T, client *kubernetes.Clientset, testNS, host string, port int32, updatedServerCert string) {
	timeout := 5 * time.Minute
	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		podName := "client-pod-" + randSeq(5)
		_, err := client.CoreV1().Pods(testNS).Create(context.TODO(), &v1.Pod{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: testNS,
			},
			Spec: v1.PodSpec{
				SecurityContext: &v1.PodSecurityContext{
					RunAsNonRoot:   pointer.BoolPtr(true),
					SeccompProfile: &v1.SeccompProfile{Type: v1.SeccompProfileTypeRuntimeDefault},
				},
				Containers: []v1.Container{
					{
						Name:    "cert-checker",
						Image:   "nicolaka/netshoot:latest",
						Command: []string{"/bin/bash"},
						Args: []string{"-c", fmt.Sprintf("openssl s_client -no-CApath -no-CAfile -CAfile /var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt "+
							"-verify_return_error -verify_hostname %s -showcerts -connect %s:%d < /dev/null 2>/dev/null | openssl x509", host, host, port)},
						SecurityContext: &v1.SecurityContext{
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities:             &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
						},
					},
				},
				RestartPolicy: v1.RestartPolicyOnFailure,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			tlogf(t, "creating client pod failed: %v", err)
			return false, nil
		}
		defer deletePod(t, client, podName, testNS)

		err = waitForPodPhase(t, client, podName, testNS, v1.PodSucceeded)
		if err != nil {
			tlogf(t, "wait on pod to complete failed: %v", err)
			return false, nil
		}

		serverCertClientReceived, err := getPodLogs(t, client, podName, testNS)
		if err != nil {
			tlogf(t, "fetching pod logs failed: %v", err)
			return false, nil
		}
		return strings.Contains(updatedServerCert, serverCertClientReceived), nil
	})
	if err != nil {
		t.Fatalf("failed to verify updated certs within timeout(%v)", timeout)
	}

}

func waitForPodPhase(t *testing.T, client *kubernetes.Clientset, name, namespace string, phase v1.PodPhase) error {
	return wait.PollImmediate(10*time.Second, time.Minute, func() (bool, error) {
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "fetching test pod from apiserver failed: %v", err)
			return false, nil
		}
		return pod.Status.Phase == phase, nil
	})
}

func getPodLogs(t *testing.T, client *kubernetes.Clientset, name, namespace string) (string, error) {
	rc, err := client.CoreV1().Pods(namespace).GetLogs(name, &v1.PodLogOptions{}).Stream(context.TODO())
	if err != nil {
		return "", err
	}
	defer rc.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rc)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func deletePod(t *testing.T, client *kubernetes.Clientset, name, namespace string) {
	err := client.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Errorf("failed to delete pod: %v", err)
	}
}

func pollForRunningStatefulSet(t *testing.T, client *kubernetes.Clientset, statefulSetName, namespace string, timeout time.Duration) error {
	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		set, err := client.AppsV1().StatefulSets(namespace).Get(context.TODO(), statefulSetName, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "fetching StatefulSet failed: %v", err)
			return false, err
		}
		res := set.Status.ObservedGeneration == set.Generation &&
			set.Status.ReadyReplicas == *set.Spec.Replicas
		return res, nil
	})
	if err != nil {
		tlogf(t, "error waiting for StatefulSet restart: %v", err)
	}
	return err
}

// newPrometheusClientForConfig returns a new prometheus client for
// the provided kubeconfig.
func newPrometheusClientForConfig(config *rest.Config) (prometheusv1.API, error) {
	routeClient, err := routeclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating route client: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kube client: %v", err)
	}
	return metrics.NewPrometheusClient(context.TODO(), kubeClient, routeClient)
}

// checkMetricsCollection tests whether metrics are being successfully scraped from at
// least one target in a namespace.
func checkMetricsCollection(t *testing.T, promClient prometheusv1.API, namespace string) {
	// Metrics are scraped every 30s. Wait as long as 2 intervals to avoid failing if
	// the target is temporarily unhealthy.
	timeout := 60 * time.Second

	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		query := fmt.Sprintf("up{namespace=\"%s\"}", namespace)
		resultVector, err := runPromQueryForVector(t, promClient, query, time.Now())
		if err != nil {
			t.Errorf("failed to execute prometheus query: %v", err)
			return false, nil
		}
		metricsCollected := false
		for _, sample := range resultVector {
			metricsCollected = sample.Value == 1
			if metricsCollected {
				// Metrics are successfully being scraped for at least one target in the namespace
				break
			}
		}
		return metricsCollected, nil
	})
	if err != nil {
		t.Fatalf("Health check of metrics collection in namespace %s did not succeed within %v", serviceCAOperatorNamespace, timeout)
	}
}

func runPromQueryForVector(t *testing.T, promClient prometheusv1.API, query string, sampleTime time.Time) (model.Vector, error) {
	results, warnings, err := promClient.Query(context.Background(), query, sampleTime)
	if err != nil {
		return nil, err
	}
	if len(warnings) > 0 {
		tlogf(t, "prometheus query emitted warnings: %v", warnings)
	}

	result, ok := results.(model.Vector)
	if !ok {
		return nil, fmt.Errorf("expecting vector type result, found: %v ", reflect.TypeOf(results))
	}

	return result, nil
}

func getSampleForPromQuery(t *testing.T, promClient prometheusv1.API, query string, sampleTime time.Time) (*model.Sample, error) {
	res, err := runPromQueryForVector(t, promClient, query, sampleTime)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no matching metrics found for query %s", query)
	}
	return res[0], nil
}

func checkServiceCAMetrics(t *testing.T, client *kubernetes.Clientset, promClient prometheusv1.API) {
	timeout := 120 * time.Second

	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	currentCACerts, err := util.PemToCerts(secret.Data[v1.TLSCertKey])
	if err != nil {
		t.Fatalf("error unmarshaling %q: %v", v1.TLSCertKey, err)
	}
	if len(currentCACerts) == 0 {
		t.Fatalf("no signing keys found")
	}

	want := currentCACerts[0].NotAfter
	err = wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		rawExpiryTime, err := getSampleForPromQuery(t, promClient, `service_ca_expiry_time_seconds`, time.Now())
		if err != nil {
			tlogf(t, "failed to get sample value: %v", err)
			return false, nil
		}
		if rawExpiryTime.Value == 0 { // The operator is starting
			tlogf(t, "got zero value")
			return false, nil
		}

		if float64(want.Unix()) != float64(rawExpiryTime.Value) {
			t.Fatalf("service ca expiry time mismatch expected %v observed %v", float64(want.Unix()), float64(rawExpiryTime.Value))
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("service ca expiry timer metrics collection failed: %v", err)
	}
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
	checkComponents(t, adminClient)

	// test the main feature. annotate service -> created secret
	t.Run("serving-cert-annotation", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
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
			})
		}
	})

	// test modified data in serving-cert-secret will regenerated
	t.Run("serving-cert-secret-modify-bad-tlsCert", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
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
				originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
				if err != nil {
					t.Fatalf("error when checking serving cert secret: %v", err)
				}

				err = editServingSecretData(t, adminClient, testSecretName, ns.Name, v1.TLSCertKey)
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
		}
	})

	// test extra data in serving-cert-secret will be removed
	t.Run("serving-cert-secret-add-data", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
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
				originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
				if err != nil {
					t.Fatalf("error when checking serving cert secret: %v", err)
				}

				err = editServingSecretData(t, adminClient, testSecretName, ns.Name, "foo")
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
		}
	})

	// make sure that deleting service-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	t.Run("serving-cert-secret-delete-data", func(t *testing.T) {
		serviceName := "metrics"
		operatorNamespace := "openshift-service-ca-operator"
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		service, err := adminClient.CoreV1().Services(operatorNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("fetching service from apiserver failed: %v", err)
		}
		secretName, ok := service.ObjectMeta.Annotations[api.ServingCertSecretAnnotation]
		if !ok {
			t.Fatalf("secret name not found in service annotations")
		}
		err = adminClient.CoreV1().Secrets(operatorNamespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("deleting secret %s in namespace %s failed: %v", secretName, operatorNamespace, err)
		}
		updatedBytes, _, err := pollForUpdatedServingCert(t, adminClient, operatorNamespace, secretName, rotationPollTimeout, nil, nil)
		if err != nil {
			t.Fatalf("error fetching re-created serving cert secret: %v", err)
		}

		metricsHost := fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace)
		checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, metricsHost, service.Spec.Ports[0].Port, string(updatedBytes))
	})

	// make sure that deleting aservice-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	t.Run("headless-stateful-serving-cert-secret-delete-data", func(t *testing.T) {
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		testServiceName := "test-service-" + randSeq(5)
		testStatefulSetName := "test-statefulset-" + randSeq(5)
		testStatefulSetSize := 3
		testSecretName := "test-secret-" + randSeq(5)

		if err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, true); err != nil {
			t.Fatalf("error creating headless service: %v", err)
		}
		oldSecret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}

		err = adminClient.CoreV1().Secrets(ns.Name).Delete(context.TODO(), testSecretName, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("deleting secret %s in namespace %s failed: %v", testSecretName, ns.Name, err)
		}
		newCertPEM, _, err := pollForUpdatedServingCert(t, adminClient, ns.Name, testSecretName, rotationPollTimeout,
			oldSecret.Data[v1.TLSCertKey], oldSecret.Data[v1.TLSPrivateKeyKey])
		if err != nil {
			t.Fatalf("error fetching re-created serving cert secret: %v", err)
		}

		if err := createStatefulSet(adminClient, testSecretName, testStatefulSetName, testServiceName, ns.Name, testStatefulSetSize); err != nil {
			t.Fatalf("error creating annotated StatefulSet: %v", err)
		}
		if err := pollForRunningStatefulSet(t, adminClient, testStatefulSetName, ns.Name, 1*time.Minute); err != nil {
			t.Fatalf("error starting StatefulSet: %v", err)
		}

		// Individual StatefulSet pods are reachable using the generated certificate
		for i := 0; i < testStatefulSetSize; i++ {
			host := fmt.Sprintf("%s-%d.%s.%s.svc", testStatefulSetName, i, testServiceName, ns.Name)
			checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, host, 8443, string(newCertPEM))
		}
		// The (headless) service is reachable using the generated certificate
		host := fmt.Sprintf("%s.%s.svc", testServiceName, ns.Name)
		checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, host, 8443, string(newCertPEM))
	})

	// test ca bundle injection configmap
	t.Run("ca-bundle-injection-configmap", func(t *testing.T) {
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		testConfigMapName := "test-configmap-" + randSeq(5)

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
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		testConfigMapName := "test-configmap-" + randSeq(5)

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

		err = editConfigMapCABundleInjectionData(t, adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error editing ca bundle injection configmap: %v", err)
		}

		err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
		if err != nil {
			t.Fatalf("error when checking ca bundle injection configmap: %v", err)
		}
	})

	// test vulnerable-legacy ca bundle injection configmap
	t.Run("vulnerable-legacy-ca-bundle-injection-configmap", func(t *testing.T) {
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		// names other than the one we need are never published to
		neverPublished := &v1.ConfigMap{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-configmap-" + randSeq(5),
				Annotations: map[string]string{api.VulnerableLegacyInjectCABundleAnnotationName: "true"},
			},
		}
		_, err = adminClient.CoreV1().ConfigMaps(ns.Name).Create(context.TODO(), neverPublished, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		// with this name, content should never be published.  We wait ten seconds
		err = pollForConfigMapCAInjection(adminClient, neverPublished.Name, ns.Name)
		if err != wait.ErrWaitTimeout {
			t.Fatal(err)
		}

		publishedConfigMap := &v1.ConfigMap{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:        "openshift-service-ca.crt",
				Annotations: map[string]string{api.VulnerableLegacyInjectCABundleAnnotationName: "true"},
			},
		}
		publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Create(context.TODO(), publishedConfigMap, metav1.CreateOptions{})
		// tolerate "already exists" to handle the case where we're running the e2e on a cluster that already has this
		// configmap present and injected.
		if err != nil && !errors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Get(context.TODO(), "openshift-service-ca.crt", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}

		// this one should be injected
		err = pollForConfigMapCAInjection(adminClient, publishedConfigMap.Name, ns.Name)
		if err != nil {
			t.Fatal(err)
		}
		originalContent := publishedConfigMap.Data[api.InjectionDataKey]

		_, hasNewStyleAnnotation := publishedConfigMap.Annotations[api.InjectCABundleAnnotationName]
		if hasNewStyleAnnotation {
			// add old injection to be sure only new is honored
			publishedConfigMap.Annotations[api.VulnerableLegacyInjectCABundleAnnotationName] = "true"
			publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Update(context.TODO(), publishedConfigMap, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		} else {
			// hand-off to new injector
			publishedConfigMap.Annotations[api.InjectCABundleAnnotationName] = "true"
			publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Update(context.TODO(), publishedConfigMap, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}

		// the content should now change pretty quick.  We sleep because it's easier than writing a new poll and I'm pressed for time
		time.Sleep(5 * time.Second)
		publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Get(context.TODO(), publishedConfigMap.Name, metav1.GetOptions{})

		// if we changed the injection, we should see different content
		if hasNewStyleAnnotation {
			if publishedConfigMap.Data[api.InjectionDataKey] != originalContent {
				t.Fatal("Content switch and it should not have.  The better ca bundle should win.")
			}
		} else {
			if publishedConfigMap.Data[api.InjectionDataKey] == originalContent {
				t.Fatal("Content did not update like it was supposed to.  The better ca bundle should win.")
			}
		}
	})

	t.Run("metrics", func(t *testing.T) {
		promClient, err := newPrometheusClientForConfig(adminConfig)
		if err != nil {
			t.Fatalf("error initializing prometheus client: %v", err)
		}
		// Test that the operator's metrics endpoint is being read by prometheus
		t.Run("collection", func(t *testing.T) {
			checkMetricsCollection(t, promClient, "openshift-service-ca-operator")
		})

		// Test that service CA metrics are collected
		t.Run("service-ca-metrics", func(t *testing.T) {
			checkServiceCAMetrics(t, adminClient, promClient)
		})
	})

	t.Run("refresh-CA", func(t *testing.T) {
		ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
		if err != nil {
			t.Fatalf("could not create test namespace: %v", err)
		}
		defer cleanup()

		// create secrets
		testServiceName := "test-service-" + randSeq(5)
		testSecretName := "test-secret-" + randSeq(5)
		testHeadlessServiceName := "test-headless-service-" + randSeq(5)
		testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

		err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, false)
		if err != nil {
			t.Fatalf("error creating annotated service: %v", err)
		}
		if err = createServingCertAnnotatedService(adminClient, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
			t.Fatalf("error creating annotated headless service: %v", err)
		}

		secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		secretCopy := secret.DeepCopy()
		headlessSecret, err := pollForServiceServingSecretWithReturn(adminClient, testHeadlessSecretName, ns.Name)
		if err != nil {
			t.Fatalf("error fetching created serving cert secret: %v", err)
		}
		headlessSecretCopy := headlessSecret.DeepCopy()

		// create configmap
		testConfigMapName := "test-configmap-" + randSeq(5)

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
		err = adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Delete(context.TODO(), signingKeySecretName, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("error deleting signing key: %v", err)
		}

		// make sure it's recreated
		err = pollForCARecreation(adminClient)
		if err != nil {
			t.Fatalf("signing key was not recreated: %v", err)
		}

		err = pollForConfigMapChange(t, adminClient, configmapCopy, api.InjectionDataKey)
		if err != nil {
			t.Fatalf("configmap bundle did not change: %v", err)
		}

		err = pollForSecretChange(t, adminClient, secretCopy, v1.TLSCertKey, v1.TLSPrivateKeyKey)
		if err != nil {
			t.Fatalf("secret cert did not change: %v", err)
		}
		if err := pollForSecretChange(t, adminClient, headlessSecretCopy); err != nil {
			t.Fatalf("headless secret cert did not change: %v", err)
		}
	})

	// This test triggers rotation by updating the CA to have an
	// expiry that is less than the minimum required duration and then
	// validates that both refreshed and unrefreshed clients and
	// servers can continue to communicate in a trusted fashion.
	t.Run("time-based-ca-rotation", func(t *testing.T) {
		checkCARotation(t, adminClient, adminConfig, triggerTimeBasedRotation)
	})

	// This test triggers rotation by updating the operator
	// configuration to force rotation and then validates that both
	// refreshed and unrefreshed clients and servers can continue to
	// communicate in a trusted fashion.
	t.Run("forced-ca-rotation", func(t *testing.T) {
		checkCARotation(t, adminClient, adminConfig, triggerForcedRotation)
	})

	t.Run("apiservice-ca-bundle-injection", func(t *testing.T) {
		client := apiserviceclient.NewForConfigOrDie(adminConfig).ApiregistrationV1().APIServices()

		// Create an api service with the injection annotation
		randomGroup := fmt.Sprintf("e2e-%s", randSeq(10))
		version := "v1alpha1"
		obj := &apiregv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s.%s", version, randomGroup),
			},
			Spec: apiregv1.APIServiceSpec{
				Group:                randomGroup,
				Version:              version,
				GroupPriorityMinimum: 1,
				VersionPriority:      1,
				// A service must be specified for validation to
				// accept a cabundle.
				Service: &apiregv1.ServiceReference{
					Namespace: "foo",
					Name:      "foo",
				},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating api service: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup api service: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the signing ca bundle: %v", err)
		}

		// Wait for the expected bundle to be injected
		injectedObj, err := pollForAPIService(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		injectedObj.Spec.CABundle = append(injectedObj.Spec.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated api service: %v", err)
		}

		// Check that the expected ca bundle is restored
		_, err = pollForAPIService(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	t.Run("crd-ca-bundle-injection", func(t *testing.T) {
		client := apiextclient.NewForConfigOrDie(adminConfig).CustomResourceDefinitions()

		// Create a crd with the injection annotation
		randomGroup := fmt.Sprintf("e2e-%s.example.com", randSeq(10))
		pluralName := "cabundleinjectiontargets"
		version := "v1beta1"
		obj := &apiext.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s.%s", pluralName, randomGroup),
			},
			Spec: apiext.CustomResourceDefinitionSpec{
				Group: randomGroup,
				Scope: apiext.ClusterScoped,
				Names: apiext.CustomResourceDefinitionNames{
					Plural: pluralName,
					Kind:   "CABundleInjectionTarget",
				},
				Conversion: &apiext.CustomResourceConversion{
					// CA bundle will only be injected for a webhook converter
					Strategy: apiext.WebhookConverter,
					Webhook: &apiext.WebhookConversion{
						// CA bundle will be set on the following struct
						ClientConfig: &apiext.WebhookClientConfig{
							Service: &apiext.ServiceReference{
								Namespace: "foo",
								Name:      "foo",
							},
						},
						ConversionReviewVersions: []string{
							version,
						},
					},
				},
				// At least one version must be defined for a v1 crd to be valid
				Versions: []apiext.CustomResourceDefinitionVersion{
					{
						Name:    version,
						Storage: true,
						Schema: &apiext.CustomResourceValidation{
							OpenAPIV3Schema: &apiext.JSONSchemaProps{
								Type: "object",
							},
						},
					},
				},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating crd: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup crd: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the signing ca bundle: %v", err)
		}

		// Wait for the expected bundle to be injected
		injectedObj, err := pollForCRD(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		whClientConfig := injectedObj.Spec.Conversion.Webhook.ClientConfig
		whClientConfig.CABundle = append(whClientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated crd: %v", err)
		}

		// Check that the expected ca bundle is restored
		_, err = pollForCRD(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	// Common webhook config
	webhookClientConfig := admissionreg.WebhookClientConfig{
		// A service must be specified for validation to
		// accept a cabundle.
		Service: &admissionreg.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
	sideEffectNone := admissionreg.SideEffectClassNone

	t.Run("mutatingwebhook-ca-bundle-injection", func(t *testing.T) {
		client := adminClient.AdmissionregistrationV1().MutatingWebhookConfigurations()
		obj := &admissionreg.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "e2e-",
			},
			Webhooks: []admissionreg.MutatingWebhook{
				// Specify 2 webhooks to ensure more than 1 webhook will be updated
				{
					Name:                    "e2e-1.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
				{
					Name:                    "e2e-2.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
			},
		}
		// webhooks to add after initial creation to ensure
		// updates can be made for more than the original number of webhooks.
		webhooksToAdd := []admissionreg.MutatingWebhook{
			{
				Name:                    "e2e-3.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating mutating webhook configuration: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup mutating webhook configuration: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the expected ca bundle: %v", err)
		}

		// Poll for the updated webhook configuration
		injectedObj, err := pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		clientConfig := injectedObj.Webhooks[0].ClientConfig
		clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated mutating webhook configuration: %v", err)
		}

		// Check that the ca bundle is restored
		injectedObj, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}

		// Add an additional webhook and make sure CA bundle exists for all
		injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updating mutating webhook configuration: %v", err)
		}

		// Check that the ca bundle for all webhooks (old and new)
		_, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})

	t.Run("validatingwebhook-ca-bundle-injection", func(t *testing.T) {
		client := adminClient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		obj := &admissionreg.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "e2e-",
			},
			Webhooks: []admissionreg.ValidatingWebhook{
				// Specify 2 webhooks to ensure more than 1 webhook will be updated
				{
					Name:                    "e2e-1.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
				{
					Name:                    "e2e-2.example.com",
					ClientConfig:            webhookClientConfig,
					SideEffects:             &sideEffectNone,
					AdmissionReviewVersions: []string{"v1beta1"},
				},
			},
		}
		// webhooks to add after initial creation to ensure
		// updates can be made for more than the original number of webhooks.
		webhooksToAdd := []admissionreg.ValidatingWebhook{
			{
				Name:                    "e2e-3.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1"},
			},
		}
		setInjectionAnnotation(&obj.ObjectMeta)
		createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("error creating validating webhook configuration: %v", err)
		}
		defer func() {
			err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Errorf("Failed to cleanup validating webhook configuration: %v", err)
			}
		}()

		// Retrieve the expected CA bundle
		expectedCABundle, err := pollForSigningCABundle(t, adminClient)
		if err != nil {
			t.Fatalf("error retrieving the expected ca bundle: %v", err)
		}

		// Poll for the updated webhook configuration
		injectedObj, err := pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be injected: %v", err)
		}

		// Set an invalid ca bundle
		clientConfig := injectedObj.Webhooks[0].ClientConfig
		clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updated validating webhook configuration: %v", err)
		}

		// Check that the ca bundle is restored
		injectedObj, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}

		// Add an additional webhook and make sure CA bundle exists for all
		injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
		_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
		if err != nil {
			t.Fatalf("error updating validating webhook configuration: %v", err)
		}

		// Check that the ca bundle for all webhooks (old and new)
		_, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
		if err != nil {
			t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
		}
	})
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
