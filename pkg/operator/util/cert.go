package util

import (
	crand "crypto/rand"
	"crypto/x509"
	"fmt"
)

// CreateCertificate creates a new certificate and returns it in x509.Certificate form.
func CreateCertificate(template, parent *x509.Certificate, pub, priv interface{}) (*x509.Certificate, error) {
	rawCert, err := x509.CreateCertificate(crand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate: %v", err)
	}
	parsedCerts, err := x509.ParseCertificates(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}
	return parsedCerts[0], nil
}
