package controller

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clientgotesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	kubediff "k8s.io/utils/diff"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/cryptoextensions"
)

const (
	serviceSignerName = "openshift-service-serving-signer"
	testServiceUID    = "some-uid"
	testServiceName   = "svc-name"
)

func serviceServingCertControllerSetup(t *testing.T, servingCA *ServingCA, service *corev1.Service, secret *corev1.Secret) (*fake.Clientset, *serviceServingCertController) {
	clientObjects := []runtime.Object{} // objects to init the kubeclient with

	svcIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if service != nil {
		if err := svcIndexer.Add(service); err != nil {
			t.Fatal(err)
			clientObjects = append(clientObjects, service)
		}
	}
	svcLister := corev1listers.NewServiceLister(svcIndexer)

	secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if secret != nil {
		if err := secretIndexer.Add(secret); err != nil {
			t.Fatal(err)
		}
		clientObjects = append(clientObjects, secret)
	}

	kubeclient := fake.NewSimpleClientset(clientObjects...)
	kubeclient.PrependReactor("create", "*", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, action.(clientgotesting.CreateAction).GetObject(), nil
	})
	kubeclient.PrependReactor("update", "*", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, action.(clientgotesting.UpdateAction).GetObject(), nil
	})

	secretLister := corev1listers.NewSecretLister(secretIndexer)

	// setup the controller
	controller := &serviceServingCertController{
		serviceClient: kubeclient.CoreV1(),
		secretClient:  kubeclient.CoreV1(),

		serviceLister: svcLister,
		secretLister:  secretLister,

		servingCA:  servingCA,
		maxRetries: 10,
	}
	return kubeclient, controller
}

func TestServiceServingCertControllerSync(t *testing.T) {
	servingCA := newTestServingCA(t, serviceSignerName)

	// add test cases
	tests := []struct {
		name                       string
		secretData                 []byte
		serviceAnnocations         map[string]string
		secretAnnotations          map[string]string
		updateSecret               bool
		updateService              bool
		secretCreateFails          bool
		useSecretQueueKey          bool
		expectedServiceAnnotations map[string]string
		expectedSecretAnnotations  map[string]string
	}{
		{
			name: "basic controller flow",
			serviceAnnocations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			expectedServiceAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:    testSecretName,
				api.AlphaServingCertCreatedByAnnotation: serviceSignerName,
				api.ServingCertCreatedByAnnotation:      serviceSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  testServiceUID,
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			updateSecret:  true,
			updateService: true,
		},
		{
			name: "basic controller flow - beta annotations",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation:         testSecretName,
				api.AlphaServingCertCreatedByAnnotation: serviceSignerName,
				api.ServingCertCreatedByAnnotation:      serviceSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			updateSecret:  true,
			updateService: true,
		},
		{
			name: "secret already exists, is annotated but has no data",
			serviceAnnocations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  testServiceUID,
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:    testSecretName,
				api.AlphaServingCertCreatedByAnnotation: serviceSignerName,
				api.ServingCertCreatedByAnnotation:      serviceSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  testServiceUID,
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			updateSecret:  true,
			updateService: true,
		},
		{
			name: "secret already exists, is annotated but has no data - beta annotations",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  testServiceUID,
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation:         testSecretName,
				api.AlphaServingCertCreatedByAnnotation: serviceSignerName,
				api.ServingCertCreatedByAnnotation:      serviceSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			updateSecret:  true,
			updateService: true,
		},
		{
			name: "secret already exists for different svc UID",
			serviceAnnocations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  "different-svc-uid",
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secret svc-namespace/new-secret does not have corresponding service UID some-uid",
				api.ServingCertErrorAnnotation:         "secret svc-namespace/new-secret does not have corresponding service UID some-uid",
				api.AlphaServingCertErrorNumAnnotation: "1",
				api.ServingCertErrorNumAnnotation:      "1",
			},
			updateService: true,
		}, {
			name: "secret already exists for different svc UID - beta annotations",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:       "different-svc-uid",
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation:        testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secret svc-namespace/new-secret does not have corresponding service UID some-uid",
				api.ServingCertErrorAnnotation:         "secret svc-namespace/new-secret does not have corresponding service UID some-uid",
				api.AlphaServingCertErrorNumAnnotation: "1",
				api.ServingCertErrorNumAnnotation:      "1",
			},
			updateService: true,
		},
		{
			name: "secret creation fails",
			serviceAnnocations: map[string]string{
				api.AlphaServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  "different-svc-uid",
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.AlphaServingCertSecretAnnotation:   testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secrets \"new-secret\" is forbidden: mom said no, it's a no then",
				api.ServingCertErrorAnnotation:         "secrets \"new-secret\" is forbidden: mom said no, it's a no then",
				api.AlphaServingCertErrorNumAnnotation: "1",
				api.ServingCertErrorNumAnnotation:      "1",
			},
			updateService:     true,
			secretCreateFails: true,
		},
		{
			name: "secret creation fails - beta annotations",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.AlphaServiceUIDAnnotation:  "different-svc-uid",
				api.AlphaServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation:        testSecretName,
				api.AlphaServingCertErrorAnnotation:    "secrets \"new-secret\" is forbidden: mom said no, it's a no then",
				api.ServingCertErrorAnnotation:         "secrets \"new-secret\" is forbidden: mom said no, it's a no then",
				api.AlphaServingCertErrorNumAnnotation: "1",
				api.ServingCertErrorNumAnnotation:      "1",
			},
			updateService:     true,
			secretCreateFails: true,
		},
		{
			name: "secret already contains the right cert",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			secretData: generateServerCertPemForCA(t, servingCA.ca),
			expectedSecretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
		},
		{
			name: "secret already contains cert data, but it is invalid",
			serviceAnnocations: map[string]string{
				api.ServingCertSecretAnnotation: testSecretName,
			},
			secretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			secretData: []byte(testCertUnknownIssuer),
			expectedServiceAnnotations: map[string]string{
				api.ServingCertSecretAnnotation:         testSecretName,
				api.AlphaServingCertCreatedByAnnotation: serviceSignerName,
				api.ServingCertCreatedByAnnotation:      serviceSignerName,
			},
			expectedSecretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  testServiceUID,
				api.ServiceNameAnnotation: testServiceName,
			},
			updateService: true,
			updateSecret:  true,
		},
		{
			name: "secret points to a non-existent service (noop)",
			secretAnnotations: map[string]string{
				api.ServiceUIDAnnotation:  "very-different-uid",
				api.ServiceNameAnnotation: "very-different-svc-name",
			},
			secretData:        []byte(testCertUnknownIssuer),
			useSecretQueueKey: true,
		},
		{
			name:              "unannotated service in queue (noop)",
			secretAnnotations: map[string]string{},
			secretData:        []byte(testCertUnknownIssuer),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopChannel := make(chan struct{})
			defer close(stopChannel)

			existingService := createTestSvc(tt.serviceAnnocations)

			var existingSecret *corev1.Secret
			secretExists := tt.secretAnnotations != nil
			if secretExists {
				existingSecret = createTestServiceSecret(tt.secretAnnotations, tt.secretData)
			}

			kubeclient, controller := serviceServingCertControllerSetup(t, servingCA, existingService, existingSecret)
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

			queueKey := namespacedObjToQueueKey(existingService)
			if tt.useSecretQueueKey {
				queueKey = serviceFromSecretQueueFunc(existingSecret)
			}
			controller.Sync(context.TODO(), newTestSyncContext(queueKey))

			foundSecret := false
			foundServiceUpdate := false
			for _, action := range kubeclient.Actions() {
				switch {
				case action.Matches("create", "secrets") && !secretExists:
					newSecret := action.(clientgotesting.CreateAction).GetObject().(*corev1.Secret)
					foundSecret = isExpectedServiceSecret(t, newSecret, existingService, tt.expectedSecretAnnotations)

				case action.Matches("update", "secrets") && secretExists:
					secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
					foundSecret = isExpectedServiceSecret(t, secret, existingService, tt.expectedSecretAnnotations)

				case action.Matches("update", "services"):
					service := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Service)
					if !reflect.DeepEqual(service.Annotations, tt.expectedServiceAnnotations) {
						t.Errorf("expected != updated: %v", kubediff.ObjectReflectDiff(tt.expectedServiceAnnotations, service.Annotations))
						continue
					}
					foundServiceUpdate = true
				}
			}

			if foundSecret != tt.updateSecret {
				t.Errorf("secret: expected update: %v, but updated: %v", tt.updateSecret, foundSecret)
			}
			if foundServiceUpdate != tt.updateService {
				t.Errorf("service: expected update: %v, but updated: %v", tt.updateService, foundServiceUpdate)
			}
		})
	}
}

/*
func TestRecreateSecretControllerFlow(t *testing.T) {} // covered by serving-cert-secret-delete-data
func TestRecreateSecretControllerFlowBetaAnnotation(t *testing.T) { // covered by serving-cert-secret-delete-data }
*/

func createTestSvc(annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			UID:         types.UID(testServiceUID),
			Name:        testServiceName,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
	}
}

func createTestServiceSecret(annotations map[string]string, pemBundle []byte) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testSecretName,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{},
	}
	if len(pemBundle) > 0 {
		s.Data[corev1.TLSCertKey] = pemBundle
	}
	return s
}

func isExpectedServiceSecret(t *testing.T, s *corev1.Secret, service *corev1.Service, expectedAnnotations map[string]string) bool {
	if s.Name != testSecretName {
		t.Errorf("expected %v, got %v", testSecretName, s.Name)
		return false
	}
	if s.Namespace != testNamespace {
		t.Errorf("expected %v, got %v", testNamespace, s.Namespace)
		return false
	}

	delete(s.Annotations, api.AlphaServingCertExpiryAnnotation)
	delete(s.Annotations, api.ServingCertExpiryAnnotation)
	if !reflect.DeepEqual(s.Annotations, expectedAnnotations) {
		t.Errorf("expected != updated: %v", kubediff.ObjectReflectDiff(expectedAnnotations, s.Annotations))
		return false
	}

	checkGeneratedServiceCertificate(t, s.Data["tls.crt"], service)
	return true
}

func checkGeneratedServiceCertificate(t *testing.T, certData []byte, service *corev1.Service) {
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
		t.Errorf("unexpected DNSNames: %v", cert.DNSNames)
	}
	for _, s := range cert.DNSNames {
		switch s {
		case fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace),
			fmt.Sprintf("%s.%s.svc.cluster.local", service.Name, service.Namespace):
		default:
			t.Errorf("unexpected DNSNames: %v", cert.DNSNames)
		}
	}

	found := true
	for _, ext := range cert.Extensions {
		if cryptoextensions.OpenShiftServerSigningServiceUIDOID.Equal(ext.Id) {
			var value string
			if _, err := asn1.Unmarshal(ext.Value, &value); err != nil {
				t.Errorf("unable to parse certificate extension: %v", ext.Value)
				continue
			}
			if value != string(service.UID) {
				t.Errorf("unexpected extension value: %v", value)
				continue
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unable to find service UID certificate extension in cert: %#v", cert)
	}
}
