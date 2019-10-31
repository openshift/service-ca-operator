package operator

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
	"github.com/openshift/service-ca-operator/test/util"
)

func caToSigningSecret(t *testing.T, caConfig *crypto.TLSCertificateConfig) (*corev1.Secret, *x509.Certificate) {
	certPEM, keyPEM, err := caConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("error converting ca to PEM: %v", err)
	}
	return &corev1.Secret{
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}, caConfig.Certs[0]
}

// TestRotateSigningSecret validates the rotation of a signing secret when required.
func TestRotateSigningSecret(t *testing.T) {
	// Create a brand new signing secret
	newCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetimeInDays)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	newSigningSecret, newCACert := caToSigningSecret(t, newCAConfig)

	// Create a secret that has been force-rotated for a reason
	forceRotatedSigningSecret := newSigningSecret.DeepCopy()
	recordForcedRotationReason(forceRotatedSigningSecret, "42")

	// Create a signing secret more than half-way past its expiry
	notBefore := time.Now().Add(-3 * time.Hour)
	notAfter := time.Now().Add(1 * time.Hour)
	halfExpiredCAConfig, err := util.RenewSelfSignedCertificate(newCAConfig, notBefore, notAfter)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}
	halfExpiredSigningSecret, halfExpiredCACert := caToSigningSecret(t, halfExpiredCAConfig)

	testCases := map[string]struct {
		secret           *corev1.Secret
		caCert           *x509.Certificate
		reason           string
		rotationExpected bool
	}{
		"Rotation not required": {
			secret: newSigningSecret,
			caCert: newCACert,
		},
		"Time-based rotation required": {
			secret:           halfExpiredSigningSecret,
			caCert:           halfExpiredCACert,
			rotationExpected: true,
		},
		"Forced rotation required": {
			secret:           newSigningSecret,
			caCert:           newCACert,
			reason:           "42",
			rotationExpected: true,
		},
		"Forced rotation required when half-expired": {
			secret:           halfExpiredSigningSecret,
			caCert:           halfExpiredCACert,
			reason:           "42",
			rotationExpected: true,
		},
		"Forced rotation not required": {
			secret:           forceRotatedSigningSecret,
			caCert:           newCACert,
			reason:           "42",
			rotationExpected: false,
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			rawUnsupportedServiceCAConfig, err := RawUnsupportedServiceCAConfig(tc.reason)
			if err != nil {
				t.Fatalf("failed to create raw unsupported config overrides: %v", err)
			}
			secret := tc.secret.DeepCopy()
			rotationMessage, err := rotateSigningSecret(secret, tc.caCert, rawUnsupportedServiceCAConfig)
			if err != nil {
				t.Fatalf("error rotating signing secret: %v", err)
			}
			rotated := len(rotationMessage) > 0
			if tc.rotationExpected != rotated {
				t.Fatalf("expected rotation %v, got %v", tc.rotationExpected, rotated)
			}
			if rotated {
				oldMap := map[string][]byte{
					corev1.TLSCertKey:       tc.secret.Data[corev1.TLSCertKey],
					corev1.TLSPrivateKeyKey: tc.secret.Data[corev1.TLSPrivateKeyKey],
					api.BundleDataKey:       nil,
					api.IntermediateDataKey: nil,
				}
				err := util.CheckData(oldMap, secret.Data)
				if err != nil {
					t.Fatalf("rotated data does not match expectations: %v", err)
				}

				if len(tc.reason) > 0 {
					// Secret should be updated with the reason
					if secret.Annotations[api.ForcedRotationReasonAnnotationName] != tc.reason {
						t.Fatalf("secret does not have '%s: %s'", api.ForcedRotationReasonAnnotationName, tc.reason)
					}
				}
			} else if !reflect.DeepEqual(secret, tc.secret) {
				t.Fatalf("secret was unexpected rotated")
			}
		})
	}
}

func TestForcedRotationRequired(t *testing.T) {
	testCases := map[string]struct {
		annotations map[string]string
		reason      string
		expected    bool
	}{
		"No rotation without a reason": {
			reason: "",
		},
		"No rotation if the stored reason matches": {
			annotations: map[string]string{
				api.ForcedRotationReasonAnnotationName: "42",
			},
			reason: "42",
		},
		"Rotation if the reason differs": {
			reason:   "42",
			expected: true,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tc.annotations,
				},
			}
			actual := forcedRotationRequired(secret, tc.reason)
			if tc.expected != actual {
				t.Fatalf("expected forced=%v, but forced=%v", tc.expected, actual)
			}
		})
	}
}

// TestRotateSigningCA validates that service certs signed by pre- and
// post-rotation CAs can be validated by both pre- and post-rotation
// old bundles.
func TestRotateSigningCA(t *testing.T) {
	// Used in generating serving certs
	dnsSuffix := "local"
	objMeta := &metav1.ObjectMeta{
		Name:      "myservice",
		Namespace: "mynamespace",
		UID:       types.UID(uuid.New().String()),
	}

	oldCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetimeInDays)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	oldCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          oldCAConfig,
	}
	oldBundlePEM, err := crypto.EncodeCertificates(oldCAConfig.Certs[0])
	if err != nil {
		t.Fatalf("error encoding old bundle to PEM: %v", err)
	}

	// Generate a service cert with the pre-rotation CA
	oldServingCert, err := controller.GetServingCert(dnsSuffix, oldCA, nil, objMeta)
	if err != nil {
		t.Fatalf("error generating serving cert from old ca: %v", err)
	}
	oldCertPEM, oldKeyPEM, err := oldServingCert.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding old serving cert to PEM: %v", err)
	}

	// Simulate forced rotation by renewing the current ca with a
	// validity bounds more than half-way expired. This is required
	// for e2e testing, and performing it here ensures that unit
	// testing is as similar as possible so that testing can be more
	// cheaply maintained.
	notBefore := time.Now().Add(-3 * time.Hour)
	notAfter := time.Now().Add(1 * time.Hour)
	renewedCAConfig, err := util.RenewSelfSignedCertificate(oldCAConfig, notBefore, notAfter)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}

	// Rotate the CA
	newSigningCA, err := rotateSigningCA(renewedCAConfig.Certs[0], renewedCAConfig.Key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("Error rotating signing ca: %v", err)
	}
	newCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newSigningCA.config,
	}
	newBundlePEM, err := crypto.EncodeCertificates(newSigningCA.bundle...)

	// Generate a service cert with the post-rotation CA
	newServingCert, err := controller.GetServingCert(dnsSuffix, newCA, newSigningCA.intermediateCACert, objMeta)
	if err != nil {
		t.Fatalf("Error generating new service cert: %v", err)
	}
	newCertPEM, newKeyPEM, err := newServingCert.GetPEMBytes()
	if err != nil {
		t.Fatalf("Error encoding new serving cert to PEM: %v", err)
	}

	// The AuthorityKeyId of the serving cert should match the CA cert's SubjectKeyId so
	// that when these values differ (i.e. when the CA is next rotated), the serving
	// cert controller will know to regenerate the serving cert.
	if bytes.Compare(newServingCert.Certs[0].AuthorityKeyId, newSigningCA.config.Certs[0].SubjectKeyId) != 0 {
		t.Fatalf("The AuthorityKeyId of the serving cert does not match the SubjectKeyId of the CA cert")
	}

	dnsName := oldServingCert.Certs[0].Subject.CommonName
	util.CheckRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)
}

func TestCertHalfwayExpired(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		testCert *x509.Certificate
		expected bool
	}{
		"expired now": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now,
			},
			expected: true,
		},
		"time left": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now.AddDate(0, 0, 2),
			},
			expected: false,
		},
		"time up": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -2),
				NotAfter:  now.AddDate(0, 0, 1),
			},
			expected: true,
		},
	}
	for name, tc := range tests {
		if certHalfwayExpired(tc.testCert) != tc.expected {
			t.Errorf("%s: unexpected result, expected %v, got %v", name, tc.expected, !tc.expected)
		}
	}
}
