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

// TestMaybeRotateSigningSecret validates the rotation of a signing secret when required.
func TestMaybeRotateSigningSecret(t *testing.T) {

	// Create a brand new signing secret
	newCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", time.Hour)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	newSigningSecret, newCACert := caToSigningSecret(t, newCAConfig)

	// Create a secret that has been force-rotated for a reason
	forceRotatedSigningSecret := newSigningSecret.DeepCopy()
	recordForcedRotationReason(forceRotatedSigningSecret, "42")

	// Create a secret whose CA expires sooner than the minimum required duration.
	expiringCAConfig, err := RenewSelfSignedCertificate(newCAConfig, 1*time.Hour, true)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}
	expiringSigningSecret, expiringCACert := caToSigningSecret(t, expiringCAConfig)

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
			secret:           expiringSigningSecret,
			caCert:           expiringCACert,
			rotationExpected: true,
		},
		"Forced rotation required": {
			secret:           newSigningSecret,
			caCert:           newCACert,
			reason:           "42",
			rotationExpected: true,
		},
		"Forced rotation required when half-expired": {
			secret:           expiringSigningSecret,
			caCert:           expiringCACert,
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
			serviceCAConfig := unsupportedServiceCAConfig{
				CAConfig: caConfig{
					ValidityDurationForTesting: 0,
				},
				ForceRotation: forceRotationConfig{
					Reason: tc.reason,
				},
			}
			secret := tc.secret.DeepCopy()
			rotationMessage, err := maybeRotateSigningSecret(secret, tc.caCert, serviceCAConfig, minimumTrustDuration, signingCertificateLifetime)
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
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "myservice",
			Namespace: "mynamespace",
			UID:       types.UID(uuid.New().String()),
		},
	}

	oldCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetime)
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
	oldServingCert, err := controller.MakeServingCert(dnsSuffix, oldCA, nil, service, time.Hour)
	if err != nil {
		t.Fatalf("error generating serving cert from old ca: %v", err)
	}
	oldCertPEM, oldKeyPEM, err := oldServingCert.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding old serving cert to PEM: %v", err)
	}

	// Simulate time-based rotation by renewing the current ca with an expiry that
	// is sooner than the minimum duration. This mirrors e2e testing to reduce the
	// cost of test maintenance.
	renewedCAConfig, err := RenewSelfSignedCertificate(oldCAConfig, 1*time.Hour, true)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}

	// Rotate the CA
	newSigningCA, err := rotateSigningCA(renewedCAConfig.Certs[0], renewedCAConfig.Key.(*rsa.PrivateKey), minimumTrustDuration, signingCertificateLifetime)
	if err != nil {
		t.Fatalf("Error rotating signing ca: %v", err)
	}
	newCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newSigningCA.config,
	}
	newBundlePEM, err := crypto.EncodeCertificates(newSigningCA.bundle...)
	if err != nil {
		t.Fatalf("Error encoding new bundle to PEM: %v", err)
	}

	// Generate a service cert with the post-rotation CA
	newServingCert, err := controller.MakeServingCert(dnsSuffix, newCA, newSigningCA.intermediateCACert, service, time.Hour)
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
	if !bytes.Equal(newServingCert.Certs[0].AuthorityKeyId, newSigningCA.config.Certs[0].SubjectKeyId) {
		t.Fatalf("The AuthorityKeyId of the serving cert does not match the SubjectKeyId of the CA cert")
	}

	// Check that trust for the old CA was extended past its renewed expiry (which
	// did not ensure the minimum trust duration).
	if !newSigningCA.oldCAExpiry.After(renewedCAConfig.Certs[0].NotAfter) {
		t.Fatalf("Trust for the old CA was not extended from the renewed expiry")
	}

	dnsName := oldServingCert.Certs[0].Subject.CommonName
	util.CheckRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)
}

// TestCreateIntermediateCACert checks that the intermediate CA cert
// created by signing a target CA cert supports identity key chaining
// and uses a serial number distinct from that of the target CA cert.
func TestCreateIntermediateCACert(t *testing.T) {
	// Create the signing CA
	signingCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetime)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	signingCACert := signingCAConfig.Certs[0]

	// Create the CA targeted for signing
	targetCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", signingCertificateLifetime)
	if err != nil {
		t.Fatalf("error generating a new ca: %v", err)
	}
	targetCACert := targetCAConfig.Certs[0]

	intermediateCACert, err := createIntermediateCACert(targetCACert, signingCACert, signingCAConfig.Key.(*rsa.PrivateKey), nil)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA cert: %v", err)
	}

	if !bytes.Equal(intermediateCACert.AuthorityKeyId, signingCACert.SubjectKeyId) {
		t.Fatalf("Expected intermediate CA cert AuthorityKeyId to match signing CA cert SubjectKeyId")
	}

	if intermediateCACert.SerialNumber.Cmp(targetCACert.SerialNumber) == 0 {
		t.Fatalf("Expected intermediate CA cert serial number to differ from serial number of target CA cert")
	}
}
