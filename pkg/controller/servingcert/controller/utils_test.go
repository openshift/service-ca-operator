package controller

import (
	"path"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	testNamespace         = "svc-namespace"
	testSecretName        = "new-secret"
	testCertUnknownIssuer = `
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUdbBKh0jOJxli4wl34q0TYJu8+n0wDQYJKoZIhvcNAQEL
BQAwKzEpMCcGA1UEAwwgb3BlbnNoaWZ0LXNlcnZpY2Utc2VydmluZy1mb29iYXIw
HhcNMTkwNDE3MTkzNDU0WhcNMjAwNDE2MTkzNDU0WjAPMQ0wCwYDVQQDDAR0ZXN0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+GyWv5JtuPjrOUrWrHkK
IgW2D5SlH0RUb5tbeuleKQLAOAovaR/rYTHsUNTmZjHnSxUfL23RGwt96/fabG/4
M8EVKyYd5pLJP3Xrzq8sA7fjSlH9YTC17GPEl7eF8acXdEF8VybGvuz7WcojDiU1
PRFV4Pgg0rHTTdgkpFreOEao3wrr2BKvF8jllhp/pf0Pm6EG3OyWbfbNUXDK62cO
92wX88wtXxb6Yps+kzbUbO5es6HoFxGDAkTC1aOIjh4Thu5RHeUlMFOYJZDeat2a
XHDCyZNFODqUnUiQdC2MMxSzTVlIwQv2vJZXdEPdNOa4ta7dn/SMTPWpspx82ugn
IwIDAQABo0kwRzALBgNVHQ8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCQYD
VR0TBAIwADAYBgNVHREEETAPgg0qLmZvby5iYXIuY29tMA0GCSqGSIb3DQEBCwUA
A4IBAQAyCaZQL70WHph9h1yc2CKgSooWQiSAU7U5mT5rc+FJdzcLaqZcQvapBgpk
Fpj1zw4cm4hjiwQceM7Zmjr+2m8aQ9b3SPxzRzCnLvYPq3jOjQSgguGTQd7edSAG
TDVO+6niXPxNLBNGWqMjTOtB/mBaXOr1Vw+8eszMFUiImlDMl6Dd0tfwgc1V7SLE
Jm4tZFG75oKIYWxo+gXLbZssVsi/wCthw+n8DE6UOo86W7YyWv9UGTGwt1wagfiR
NLnkOmhMNgDRXebZOq2vR6SWhdkbuq4FIDrfzU3iM/9r2ATJv4/tJZDqZGZAx8xf
Cryo2APfUHF0zOtxK0JifCnYi47H
-----END CERTIFICATE-----
`
)

type secretModifier func(*corev1.Secret) *corev1.Secret

func newTestServingCA(t *testing.T, name string) *ServingCA {
	// prepare the certs
	certDir := t.TempDir()

	ca, err := crypto.MakeSelfSignedCA(
		path.Join(certDir, "service-signer.crt"),
		path.Join(certDir, "service-signer.key"),
		path.Join(certDir, "service-signer.serial"),
		name,
		0,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return NewServingCA(ca, nil, "cluster.local")
}

func generateServerCertPemForCA(t *testing.T, ca *crypto.CA) []byte {
	newServingCert, err := ca.MakeServerCert(
		sets.NewString("foo"),
		crypto.DefaultCertificateLifetimeInDays,
	)
	if err != nil {
		t.Fatalf("failed to generate serving cert: %v", err)
	}
	certPEM, err := crypto.EncodeCertificates(newServingCert.Certs[0])
	if err != nil {
		t.Fatalf("failed to encode serving cert to PEM: %v", err)
	}

	return certPEM
}

type testSyncContext struct {
	queueKey      string
	eventRecorder events.Recorder
}

func (c testSyncContext) Queue() workqueue.RateLimitingInterface {
	return nil
}

func (c testSyncContext) QueueKey() string {
	return c.queueKey
}

func (c testSyncContext) Recorder() events.Recorder {
	return c.eventRecorder
}

func newTestSyncContext(queueKey string) factory.SyncContext {
	return testSyncContext{
		queueKey:      queueKey,
		eventRecorder: events.NewInMemoryRecorder("test"),
	}
}
