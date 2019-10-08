package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/operator/util"
)

// RenewSelfSignedCertificate generates a new CA with an incremented serial number and
// updated validity bounds.
func RenewSelfSignedCertificate(caConfig *crypto.TLSCertificateConfig, notBefore, notAfter time.Time) (*crypto.TLSCertificateConfig, error) {
	caCert := caConfig.Certs[0]

	// Copy the ca cert to avoid modifying the one provided
	template, err := x509.ParseCertificate(caCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to copy ca certificate: %v", err)
	}

	// Increment the serial
	template.SerialNumber = template.SerialNumber.Add(template.SerialNumber, big.NewInt(1))

	// Update the validity bounds
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	renewedCACert, err := util.CreateCertificate(template, template, caCert.PublicKey, caConfig.Key)
	if err != nil {
		return nil, fmt.Errorf("error creating ca certificate: %v", err)
	}

	return &crypto.TLSCertificateConfig{
		Certs: []*x509.Certificate{renewedCACert},
		Key:   caConfig.Key,
	}, nil
}

func PemToKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	keyASN1, err := pemToASN1(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pem-encoded private key: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyASN1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return key, nil
}

func PemToCerts(certPEM []byte) ([]*x509.Certificate, error) {
	certASN1, err := pemToASN1(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pem-encoded certificate(s): %v", err)
	}
	certs, err := x509.ParseCertificates(certASN1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate(s): %v", err)
	}
	return certs, nil
}

func pemToASN1(pemData []byte) ([]byte, error) {
	asn1Data := []byte{}
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("PEM not parsed")
		}
		asn1Data = append(asn1Data, block.Bytes...)
		if len(rest) == 0 {
			break
		}
	}
	return asn1Data, nil
}
