package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	appslistersv1 "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	kubediff "k8s.io/utils/diff"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

const (
	statefulSetSignerName = "openshift-StatefulSet-serving-signer"
	testStatefulSetUID    = "some-StatefulSet-uid"
	testStatefulSetName   = "statefulset-name"
)

func statefulSetServingCertControllerSetup(t *testing.T, servingCA *ServingCA, statefulSet *appsv1.StatefulSet, secret *corev1.Secret) (*fake.Clientset, *statefulSetServingCertController) {
	clientObjects := []runtime.Object{} // objects to init the kubeclient with

	statefulSetIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if statefulSet != nil {
		if err := statefulSetIndexer.Add(statefulSet); err != nil {
			t.Fatal(err)
			clientObjects = append(clientObjects, statefulSet)
		}
	}
	statefulSetLister := appslistersv1.NewStatefulSetLister(statefulSetIndexer)

	secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if secret != nil {
		if err := secretIndexer.Add(secret); err != nil {
			t.Fatal(err)
		}
		clientObjects = append(clientObjects, secret)
	}
	secretLister := corev1listers.NewSecretLister(secretIndexer)

	kubeclient := fake.NewSimpleClientset(clientObjects...)
	kubeclient.PrependReactor("create", "*", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, action.(clientgotesting.CreateAction).GetObject(), nil
	})
	kubeclient.PrependReactor("update", "*", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, action.(clientgotesting.UpdateAction).GetObject(), nil
	})

	// setup the controller
	controller := &statefulSetServingCertController{
		statefulSetClient: kubeclient.AppsV1(),
		secretClient:      kubeclient.CoreV1(),

		statefulSetLister: statefulSetLister,
		secretLister:      secretLister,

		servingCA:  servingCA,
		maxRetries: 10,
	}
	return kubeclient, controller
}

func TestStatefulSetServingCertControllerSync(t *testing.T) {
	servingCA := newTestServingCA(t, statefulSetSignerName)

	// add test cases
	tests := []struct {
		name                           string
		secretData                     []byte
		statefulSetAnnotations         map[string]string
		secretAnnotations              map[string]string
		updateSecret                   bool
		updateStatefulSet              bool
		secretCreateFails              bool
		useSecretQueueKey              bool
		expectedStatefulSetAnnotations map[string]string
		expectedSecretAnnotations      map[string]string
	}{
		{
			name: "basic controller flow",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:    testSecretName,
				api.AlphaServingCertCreatedByAnnotation: statefulSetSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			updateSecret:      true,
			updateStatefulSet: true,
		},
		{
			name: "secret already exists, is annotated but has no data",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:    testSecretName,
				api.AlphaServingCertCreatedByAnnotation: statefulSetSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			updateSecret:      true,
			updateStatefulSet: true,
		},
		{
			name: "secret already exists for different StatefulSet UID",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  "different-StatefulSet-uid",
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secret svc-namespace/new-secret does not have corresponding StatefulSet UID some-StatefulSet-uid",
				api.AlphaServingCertErrorNumAnnotation: "1",
			},
			updateStatefulSet: true,
		},
		{
			name: "secret creation fails",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  "different-StatefulSet-uid",
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secrets \"new-secret\" is forbidden: mom said no, it's a no then",
				api.AlphaServingCertErrorNumAnnotation: "1",
			},
			updateStatefulSet: true,
			secretCreateFails: true,
		},
		{
			name: "secret already contains the right cert",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			secretData: generateServerCertPemForCA(t, servingCA.ca),
			expectedSecretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
		},
		{
			name: "secret already contains cert data, but it is invalid",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			secretData: []byte(testCertUnknownIssuer),
			expectedStatefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:    testSecretName,
				api.AlphaServingCertCreatedByAnnotation: statefulSetSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			updateStatefulSet: true,
			updateSecret:      true,
		},
		{
			name: "secret contains cert data, but it is invalid, and StatefulSet has too many failures (noop)",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "too many past errors",
				api.AlphaServingCertErrorNumAnnotation: "10000000",
			},
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  testStatefulSetUID,
				api.AlphaStatefulSetNameAnnotation: testStatefulSetName,
			},
			secretData: []byte(testCertUnknownIssuer),
		},
		{
			name: "secret does not exist, and StatefulSet has too many failures (noop)",
			statefulSetAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "too many past errors",
				api.AlphaServingCertErrorNumAnnotation: "10000000",
			},
		},
		{
			name: "secret points to a non-existent StatefulSet (noop)",
			secretAnnotations: map[string]string{
				api.AlphaStatefulSetUIDAnnotation:  "very-different-uid",
				api.AlphaStatefulSetNameAnnotation: "very-different-statefulset-name",
			},
			secretData:        []byte(testCertUnknownIssuer),
			useSecretQueueKey: true,
		},
		{
			name:              "unannotated StatefulSet in queue (noop)",
			secretAnnotations: map[string]string{},
			secretData:        []byte(testCertUnknownIssuer),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existingStatefulSet := createTestStatefulSet(tt.statefulSetAnnotations)

			var existingSecret *corev1.Secret
			secretExists := tt.secretAnnotations != nil
			if secretExists {
				existingSecret = createTestStatefulSetSecret(tt.secretAnnotations, tt.secretData)
			}

			kubeclient, controller := statefulSetServingCertControllerSetup(t, servingCA, existingStatefulSet, existingSecret)
			if secretExists {
				// make the first secrets.Create fail with already exists because the kubeclient.CoreV1() derivate does not contain the actual object
				kubeclient.PrependReactor("create", "secrets", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.Secret{}, kapierrors.NewAlreadyExists(corev1.Resource("secrets"), "new-secret")
				})
			}

			if tt.secretCreateFails {
				kubeclient.PrependReactor("create", "secrets", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.Secret{}, kapierrors.NewForbidden(corev1.Resource("secrets"), "new-secret", fmt.Errorf("mom said no, it's a no then"))
				})
			}

			queueKey := namespacedObjToQueueKey(existingStatefulSet)
			if tt.useSecretQueueKey {
				queueKey = statefulSetFromSecretQueueFunc(existingSecret)
			}
			controller.Sync(context.TODO(), newTestSyncContext(queueKey))

			foundSecret := false
			foundStatefulSetUpdate := false
			for _, action := range kubeclient.Actions() {
				switch {
				case action.Matches("create", "secrets") && !secretExists:
					newSecret := action.(clientgotesting.CreateAction).GetObject().(*corev1.Secret)
					foundSecret = isExpectedStatefulSetSecret(t, newSecret, existingStatefulSet, tt.expectedSecretAnnotations)

				case action.Matches("update", "secrets") && secretExists:
					secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
					foundSecret = isExpectedStatefulSetSecret(t, secret, existingStatefulSet, tt.expectedSecretAnnotations)

				case action.Matches("update", "statefulsets"):
					statefulSet := action.(clientgotesting.UpdateAction).GetObject().(*appsv1.StatefulSet)
					if !reflect.DeepEqual(statefulSet.Annotations, tt.expectedStatefulSetAnnotations) {
						t.Errorf("expected != updated: %v", kubediff.ObjectReflectDiff(tt.expectedStatefulSetAnnotations, statefulSet.Annotations))
						continue
					}
					foundStatefulSetUpdate = true
				}
			}

			if foundSecret != tt.updateSecret {
				t.Errorf("secret: expected update: %v, but updated: %v", tt.updateSecret, foundSecret)
			}
			if foundStatefulSetUpdate != tt.updateStatefulSet {
				t.Errorf("StatefulSet: expected update: %v, but updated: %v", tt.updateStatefulSet, foundStatefulSetUpdate)
			}
		})
	}
}

/*
func TestRecreateSecretControllerFlow(t *testing.T) {} // covered by serving-cert-secret-delete-data
func TestRecreateSecretControllerFlowBetaAnnotation(t *testing.T) { // covered by serving-cert-secret-delete-data }
*/

func createTestStatefulSet(annotations map[string]string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			UID:         types.UID(testStatefulSetUID),
			Name:        testStatefulSetName,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
	}
}

func createTestStatefulSetSecret(annotations map[string]string, pemBundle []byte) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testSecretName,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}
	if len(pemBundle) > 0 {
		for i := 0; i < 10; i++ {
			s.Data[fmt.Sprintf("%d.crt", i)] = pemBundle
			s.Data[fmt.Sprintf("%d.key", i)] = []byte("a fake private key")
		}
	}
	return s
}

func isExpectedStatefulSetSecret(t *testing.T, s *corev1.Secret, statefulSet *appsv1.StatefulSet, expectedAnnotations map[string]string) bool {
	if s.Name != testSecretName {
		t.Errorf("expected %v, got %v", testSecretName, s.Name)
		return false
	}
	if s.Namespace != testNamespace {
		t.Errorf("expected %v, got %v", testNamespace, s.Namespace)
		return false
	}

	delete(s.Annotations, api.AlphaServingCertExpiryAnnotation)
	if !reflect.DeepEqual(s.Annotations, expectedAnnotations) {
		t.Errorf("expected != updated: %v", kubediff.ObjectReflectDiff(expectedAnnotations, s.Annotations))
		return false
	}

	checkGeneratedStatefulSetCertificates(t, s.Data, statefulSet)
	return true
}

func checkGeneratedStatefulSetCertificates(t *testing.T, secretData map[string][]byte, statefulSet *appsv1.StatefulSet) {
	pendingSecretKeys := map[string]struct{}{}
	for key := range secretData {
		pendingSecretKeys[key] = struct{}{}
	}

	numCerts := desiredCertsForStatefulSetSecret(statefulSet)
	if numCerts < 1 || (statefulSet.Spec.Replicas != nil && numCerts < int(*statefulSet.Spec.Replicas)) {
		t.Errorf("too few desired certificates: %d for %#v replicas", numCerts, statefulSet.Spec.Replicas)
		return
	}
	for i := 0; i < numCerts; i++ {
		certKey := fmt.Sprintf("%d.crt", i)
		keyKey := fmt.Sprintf("%d.key", i)
		if _, ok := secretData[keyKey]; !ok {
			t.Errorf("missing private key %s in secret", keyKey)
			return
		}
		delete(pendingSecretKeys, keyKey)

		certData, ok := secretData[certKey]
		if !ok {
			t.Errorf("missing certificate %s in secret", certKey)
			return
		}
		delete(pendingSecretKeys, certKey)

		block, _ := pem.Decode(certData)
		if block == nil {
			t.Errorf("PEM block not found in secret")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("expected valid certificate in first position: %v", err)
			return
		}

		if len(cert.DNSNames) != 2 {
			t.Errorf("unexpected DNSNames in %s: %v", certKey, cert.DNSNames)
		}
		for _, s := range cert.DNSNames {
			switch s {
			case fmt.Sprintf("%s-%d.%s.%s.svc", statefulSet.Name, i, statefulSet.Spec.ServiceName, statefulSet.Namespace),
				fmt.Sprintf("%s-%d.%s.%s.svc.cluster.local", statefulSet.Name, i, statefulSet.Spec.ServiceName, statefulSet.Namespace):
			default:
				t.Errorf("unexpected DNSNames in %s: %v", certKey, cert.DNSNames)
			}
		}
	}

	if len(pendingSecretKeys) != 0 {
		t.Errorf("unexpected secret keys: %#v", pendingSecretKeys)
	}
}
