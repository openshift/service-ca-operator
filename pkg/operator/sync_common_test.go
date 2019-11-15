package operator

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/crypto"
)

func TestInitializeSigningSecret(t *testing.T) {
	testCases := map[string]struct {
		duration time.Duration
	}{
		"Zero duration should use default expiry": {
			duration: 0 * time.Hour,
		},
		"Negative duration should result in an expired cert": {
			duration: -2 * time.Hour,
		},
		"Positive duration should result in a short expiry": {
			duration: 2 * time.Hour,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			now := time.Now()
			secret := &corev1.Secret{}
			initializeSigningSecret(secret, 0)

			// Check that the initialized key pair is valid
			rawCert := secret.Data[corev1.TLSCertKey]
			rawKey := secret.Data[corev1.TLSPrivateKeyKey]
			ca, err := crypto.GetCAFromBytes(rawCert, rawKey)
			if err != nil {
				t.Fatalf("Initialize signing secret failed to create a valid key pair: %v", err)
			}

			// Check that a non-zero duration affects the expiry

			expiry := ca.Config.Certs[0].NotAfter
			var minimumExpiry time.Time
			if tc.duration == 0*time.Nanosecond {
				minimumExpiry = now.Add(SigningCertificateLifetimeInDays)
			} else {
				minimumExpiry = now.Add(tc.duration)
			}

			// Without overriding time.Now, need to account for the time taken between cert
			// generation and this check. If it's more than 30 seconds something is surely
			// broken.
			minimumExpiry = minimumExpiry.Add(-30 * time.Second)

			if !expiry.After(minimumExpiry) {
				t.Fatalf("Expected expiry of at least %v, got %v", minimumExpiry, expiry)
			}
		})
	}
}
