package operator

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/operator/util"
)

// maybeUpdateExpiry updates the expiry of the self-signed CA and returns it if the
// provided duration is greater than zero. If an error occurs or the duration is
// zero, the original CA is returned.
func maybeUpdateExpiry(caConfig *crypto.TLSCertificateConfig, duration time.Duration) (*crypto.TLSCertificateConfig, error) {
	if duration.Nanoseconds() == 0 {
		return caConfig, nil
	}
	// operator-go's cert generation only accepts an expiry in days. To
	// ensure support for all validity durations, even those less than a
	// day, renew the self-signed cert.
	renewedCAConfig, err := RenewSelfSignedCertificate(caConfig, duration, false)
	if err != nil {
		return caConfig, err
	}
	return renewedCAConfig, nil
}

// RenewSelfSignedCertificate updates the expiry and optionally the serial number of the
// provided self-signed CA.
func RenewSelfSignedCertificate(caConfig *crypto.TLSCertificateConfig, duration time.Duration, incrementSerial bool) (*crypto.TLSCertificateConfig, error) {
	caCert := caConfig.Certs[0]

	// Copy the ca cert to avoid modifying the one provided
	template, err := x509.ParseCertificate(caCert.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to copy ca certificate: %v", err)
	}

	// Update the expiry
	expiry := time.Now().Add(duration)
	template.NotAfter = expiry

	if incrementSerial {
		template.SerialNumber = template.SerialNumber.Add(template.SerialNumber, big.NewInt(1))
	}

	renewedCACert, err := util.CreateCertificate(template, template, caCert.PublicKey, caConfig.Key)
	if err != nil {
		return nil, fmt.Errorf("error creating ca certificate: %v", err)
	}

	return &crypto.TLSCertificateConfig{
		Certs: []*x509.Certificate{renewedCACert},
		Key:   caConfig.Key,
	}, nil
}
