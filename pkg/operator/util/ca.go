package util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	cryptohelpers "github.com/openshift/library-go/pkg/crypto"
)

const SignerDays = 356

// CertHalfwayExpired returns true if half of the cert validity period has elapsed, false if not.
func CertHalfwayExpired(cert *x509.Certificate) bool {
	now := time.Now()
	halfValidPeriod := cert.NotAfter.Sub(cert.NotBefore).Nanoseconds() / 2
	halfExpiration := cert.NotBefore.Add(time.Duration(halfValidPeriod) * time.Nanosecond)
	return now.After(halfExpiration)
}

// RotateSigningCA creates a new CA with a set of cross-signed interim CAs to allow for graceful rollover.
// Returns new CA pem, new CA key pem, signed-by-old-key CA pem, full client CA bundle, err.
func RotateSigningCA(currentCA *x509.Certificate, currentCAKey *rsa.PrivateKey) ([]byte, []byte, []byte, []byte, error) {

	// Create the new CA
	newCACert, newCAKey, newCACertPem, newCAKeyPem, err := createServiceSigner(currentCA.Subject, SignerDays)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The first interim CA comprises of the old CA's public key, private key, and subject. It's self-issued but not
	// self-signed as it's signed by the new CA key. This creates a trust bridge between refreshed clients and
	// unrefreshed servers.
	signedByNew, err := x509.CreateCertificate(crand.Reader, currentCA, currentCA, currentCA.PublicKey, newCAKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// The second interim CA comprises of the new CA's public key, private key, and subject. It's self-issued but not
	// self-signed as it's signed by the old CA key. This creates a trust bridge between the unrefreshed clients and
	// refreshed servers, as long as refreshed servers serve with a bundle containing this CA and the serving cert.
	signedByOld, err := x509.CreateCertificate(crand.Reader, newCACert, newCACert, newCACert.PublicKey, currentCAKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Assemble bundle.
	signedByNewPem, err := encodeASN1Cert(signedByNew)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signedByOldPem, err := encodeASN1Cert(signedByOld)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Pem encode the current CA to include in the bundle.
	currentCACertPem, err := encodeASN1Cert(currentCA.Raw)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	bundle := make([]byte, 0)
	bundle = append(bundle, currentCACertPem...)
	bundle = append(bundle, signedByNewPem...)
	bundle = append(bundle, signedByOldPem...)
	bundle = append(bundle, newCACertPem...)

	return newCACertPem, newCAKeyPem, signedByOldPem, bundle, nil
}

func createServiceSigner(caSubject pkix.Name, days int) (*x509.Certificate, crypto.PrivateKey, []byte, []byte, error) {
	// XXX set subjectKeyId
	replacementCATemplate := &x509.Certificate{
		Subject: caSubject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    time.Now().Add(-1 * time.Second),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		SerialNumber: big.NewInt(1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	replacementCAPublicKey, replacementCAPrivateKey, err := cryptohelpers.NewKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	replacementDer, err := x509.CreateCertificate(crand.Reader, replacementCATemplate, replacementCATemplate, replacementCAPublicKey, replacementCAPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	replacementCert, err := x509.ParseCertificates(replacementDer)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(replacementCert) != 1 {
		return nil, nil, nil, nil, fmt.Errorf("Expected one certificate")
	}

	caPem, err := encodeCertificates(replacementCert...)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	caKey, err := encodeKey(replacementCAPrivateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return replacementCert[0], replacementCAPrivateKey, caPem, caKey, nil
}

func encodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

func encodeKey(key crypto.PrivateKey) ([]byte, error) {
	b := bytes.Buffer{}
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return []byte{}, err
		}
		if err := pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
			return b.Bytes(), err
		}
	case *rsa.PrivateKey:
		if err := pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			return []byte{}, err
		}
	default:
		return []byte{}, errors.New("Unrecognized key type")

	}
	return b.Bytes(), nil
}

func encodeASN1Cert(certDer []byte) ([]byte, error) {
	b := bytes.Buffer{}
	err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func parsePemCert(certPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, fmt.Errorf("error parsing certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePemKey(keyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("error parsing key pem")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
