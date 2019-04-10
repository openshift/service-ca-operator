package util

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"k8s.io/client-go/util/cert"

	cryptohelpers "github.com/openshift/library-go/pkg/crypto"
)

/*
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            43:ef:3c:b3:92:3a:b0:0d:08:35:a2:e2:ab:87:d2:31:2a:21:16:df
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: O = openshift, CN = signing-ca
        Validity
            Not Before: Nov 13 00:27:00 2018 GMT
            Not After : Nov 12 00:27:00 2023 GMT
        Subject: O = openshift, CN = signing-ca
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c0:9a:96:f3:af:ef:dc:8d:0f:c9:c6:23:ed:3b:
                    22:3b:bf:72:f7:de:c6:d2:b7:e0:a9:02:5d:4f:80:
                    01:8b:97:ff:b8:d8:92:80:82:f0:62:a0:cb:c9:d2:
                    b5:e7:c3:9c:7b:76:ab:5f:39:47:10:41:4f:b3:96:
                    83:55:ca:b5:42:20:ef:93:e9:bc:a1:d1:d8:23:a7:
                    fd:aa:e1:b0:d8:72:59:ea:33:3d:8c:ed:12:c4:a9:
                    4c:a8:25:ac:7c:df:8c:e7:d0:ba:19:c5:f4:41:c9:
                    d2:7a:d3:17:88:16:15:53:b8:79:3e:81:e6:1c:6c:
                    75:43:ef:6c:6e:1c:b2:e2:ef:8b:11:03:e4:de:36:
                    3f:35:86:dd:22:1f:75:73:0d:bc:88:a5:2d:cc:c9:
                    de:18:08:1e:f2:1d:fb:8e:72:8d:3a:fe:24:11:ee:
                    6f:fe:04:12:e7:12:81:9f:d2:01:9c:f2:5c:bb:05:
                    20:81:e2:a9:6b:07:03:00:0c:1e:46:0b:bd:26:65:
                    b1:bc:93:68:69:bc:5a:54:6d:f7:66:54:1d:19:03:
                    7f:87:2f:8f:f9:e2:0b:f2:95:06:b2:13:90:06:da:
                    8c:05:4e:1a:95:16:79:1e:41:e3:dd:41:12:57:2a:
                    44:3d:8c:2a:57:b5:7b:c0:41:8c:c0:e0:6c:5a:94:
                    3e:bd
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:2
            X509v3 Subject Key Identifier:
                95:E4:E2:A5:F0:7D:24:E5:91:CB:C5:ED:97:1D:5D:D1:D5:BB:40:FB
            X509v3 Authority Key Identifier:
                keyid:95:E4:E2:A5:F0:7D:24:E5:91:CB:C5:ED:97:1D:5D:D1:D5:BB:40:FB
    Signature Algorithm: sha256WithRSAEncryption
         b3:76:c2:83:0d:db:d3:0c:05:11:68:23:38:f3:fa:92:9f:8c:
         82:c8:02:c8:85:3a:cb:e8:03:9f:2e:80:64:ea:d6:e8:44:e3:
         c5:9b:fb:21:3f:70:78:b4:5e:33:bf:3a:c1:f8:eb:93:1e:76:
         e8:0d:84:6c:a7:4b:a3:b6:bb:9d:e0:22:5b:8c:9d:cd:84:5c:
         3a:3e:a1:4a:24:2c:49:d5:35:c5:25:7e:26:b1:70:7c:81:5a:
         d5:d3:1d:5e:0b:a8:d8:87:89:2e:dd:bf:49:f6:f2:71:ee:63:
         c3:1b:4b:68:26:28:ad:54:b1:28:43:68:27:d9:6d:7d:0a:17:
         eb:5e:11:3f:00:fa:74:1a:e4:03:69:9f:9a:58:12:2b:b6:dc:
         d4:3b:f9:91:dc:78:b1:f8:63:d4:22:38:ea:86:80:cb:f4:4f:
         7a:a0:36:ca:de:34:7f:65:df:0b:70:59:aa:82:c2:99:63:cd:
         11:57:dd:3e:e5:93:15:7d:a1:75:2f:17:6d:8a:4a:63:1b:7d:
         8d:12:af:27:8b:31:37:73:67:69:cb:4b:25:e4:98:44:ae:f7:
         ee:bf:99:38:dd:9a:9e:46:4d:00:7e:62:ec:2e:22:d8:4c:f1:
         ce:d7:89:87:5b:c0:2d:17:38:a5:d2:e7:55:09:fe:2b:64:6f:
         47:16:1c:fe
*/
const testCAPem = `
-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIUQ+88s5I6sA0INaLiq4fSMSohFt8wDQYJKoZIhvcNAQEL
BQAwKTESMBAGA1UEChMJb3BlbnNoaWZ0MRMwEQYDVQQDEwpzaWduaW5nLWNhMB4X
DTE4MTExMzAwMjcwMFoXDTIzMTExMjAwMjcwMFowKTESMBAGA1UEChMJb3BlbnNo
aWZ0MRMwEQYDVQQDEwpzaWduaW5nLWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAwJqW86/v3I0PycYj7TsiO79y997G0rfgqQJdT4ABi5f/uNiSgILw
YqDLydK158Oce3arXzlHEEFPs5aDVcq1QiDvk+m8odHYI6f9quGw2HJZ6jM9jO0S
xKlMqCWsfN+M59C6GcX0QcnSetMXiBYVU7h5PoHmHGx1Q+9sbhyy4u+LEQPk3jY/
NYbdIh91cw28iKUtzMneGAge8h37jnKNOv4kEe5v/gQS5xKBn9IBnPJcuwUggeKp
awcDAAweRgu9JmWxvJNoabxaVG33ZlQdGQN/hy+P+eIL8pUGshOQBtqMBU4alRZ5
HkHj3UESVypEPYwqV7V7wEGMwOBsWpQ+vQIDAQABo2YwZDAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUleTipfB9JOWRy8Xtlx1d
0dW7QPswHwYDVR0jBBgwFoAUleTipfB9JOWRy8Xtlx1d0dW7QPswDQYJKoZIhvcN
AQELBQADggEBALN2woMN29MMBRFoIzjz+pKfjILIAsiFOsvoA58ugGTq1uhE48Wb
+yE/cHi0XjO/OsH465MedugNhGynS6O2u53gIluMnc2EXDo+oUokLEnVNcUlfiax
cHyBWtXTHV4LqNiHiS7dv0n28nHuY8MbS2gmKK1UsShDaCfZbX0KF+teET8A+nQa
5ANpn5pYEiu23NQ7+ZHceLH4Y9QiOOqGgMv0T3qgNsreNH9l3wtwWaqCwpljzRFX
3T7lkxV9oXUvF22KSmMbfY0SryeLMTdzZ2nLSyXkmESu9+6/mTjdmp5GTQB+Yuwu
IthM8c7XiYdbwC0XOKXS51UJ/itkb0cWHP4=
-----END CERTIFICATE-----
`
const testCAKeyPem = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwJqW86/v3I0PycYj7TsiO79y997G0rfgqQJdT4ABi5f/uNiS
gILwYqDLydK158Oce3arXzlHEEFPs5aDVcq1QiDvk+m8odHYI6f9quGw2HJZ6jM9
jO0SxKlMqCWsfN+M59C6GcX0QcnSetMXiBYVU7h5PoHmHGx1Q+9sbhyy4u+LEQPk
3jY/NYbdIh91cw28iKUtzMneGAge8h37jnKNOv4kEe5v/gQS5xKBn9IBnPJcuwUg
geKpawcDAAweRgu9JmWxvJNoabxaVG33ZlQdGQN/hy+P+eIL8pUGshOQBtqMBU4a
lRZ5HkHj3UESVypEPYwqV7V7wEGMwOBsWpQ+vQIDAQABAoIBAA7Nkt6F3iyYVudO
KEK6ccYfz8lHQQa/BTBYMy3CC9xbwVbGpnPkHG+oJiGL5Vk7ypIeq8s0zsZsDqEh
51Q3sTi06VT3+PyC8VbEOZXhpMLt/wUmDQwAyJl+3Zpq0tgCIoVKoJMMiNpplZjF
EqDt+ZOmsQLh3vq+R0ECbNYFtKYGWv8JnDUPhVGUqCSBfhQhKZ9v8G7MjdWLMQdS
WPSJEoI7WGmvwE/YdOBDyaMUpuBBsp1/b4e8Tpvt03E/jThRrzoFhwYLCEZ3TAAy
f3nWhHntV/SgfVjmvpjxy3TWRaU4+EbG/kVHkwRqL98cTZMSTAuzvCDk32P/oIgW
WEaFT4ECgYEA6eTxFNHlZylIcXLXGGOP7aO7VY6ozrPt0x5Lcx1kBPR+WuQzzIHs
3v6vTPdz+TwCBAOO9gVfr3AnwTZU+x7OQPGydWCSU+CUft3oqOI176roLSf0Lnr9
77yQ/7UOBcSwfeBZ3zNoftaOsZIl8s09UOKD4BWtAr8Av60xof7eR50CgYEA0s6g
2mHQv5ir6M4Mt6Xd+saLA47WkiftCKm4mUUxwESTRPvpzaNjp/PxD2kTrfe0R3o3
WKAywkPVRtDUvm1HxlJx0rfkGCt1SgfaC/h0Qda2Iyh41Ahqdpd53hgF3w70Dg44
13+scBcnHHmM1RAOcAbUDTy/UpasrFxeA0mweaECgYEAl+uky6kqID+oVkgJfkXt
DqXy4DexXdFxAFgFGdhVRwKnr9HZ81PQz2cN5ig0pAZeKM1G5nXHGOT4bX8k45e2
0GgtSiBX6zNMQLtSi5+i+PFBrVLuP+KTXkxUwkKPwR9oo9o9hcSWcwxZ0uziyTqW
QRtgHQT3Q3lcuyN7wYUSS+ECgYAvXiqap3wGcUG/j/0fju+wF8jIxeHE+Z+zYJ+Q
IRIqx73ntEs2383WwWObONspLg2eOgIRsf111VQpE2eaWmfUUlYtKRDhtXInblg6
dFt7J8nJYKC11CZH+4VwuCkpk+yW8+8lzRRsI2ewaEeS4Ia9+WrQhqPe5Ohr2l1t
k7NJwQKBgBnbaUVjN58TDbxIRKehr0ArfnAWYIWaU2Rdz9FhbX5Sy/wU7QGaGLvj
banqV7hCbcu2pU3vaEQgeArDHyv/pSCxRAlr+vlqo55uWrXILgKFyOvGAkzw3fwO
1/omXMBe9HpQcc0nu1U4PYE0wONMBV+VVdA2FZTKydiJxEOfvCGk
-----END RSA PRIVATE KEY-----
`

func TestRotateSigningCA(t *testing.T) {
	tests := map[string]struct {
		caCertPem   []byte
		caKeyPem    []byte
		bundleNum   int
		expectedErr error
	}{
		"test": {
			caCertPem: []byte(testCAPem),
			caKeyPem:  []byte(testCAKeyPem),
			bundleNum: 4,
		},
	}

	for name, tc := range tests {
		caCert, err := parsePemCert(tc.caCertPem)
		if err != nil {
			t.Fatalf("%s: error parsing cert: %v", name, err)
		}

		caKey, err := parsePemKey(tc.caKeyPem)
		if err != nil {
			t.Fatalf("%s: error parsing key: %v", name, err)
		}

		newCAPem, newCAKeyPem, interim, bundle, err := RotateSigningCA(caCert, caKey)
		if err != nil {
			if tc.expectedErr == nil {
				t.Fatalf("%s: error rotating signing CA: %v", name, err)
			} else if tc.expectedErr != err {
				t.Fatalf("%s: unexpected error: got %v, expected %v", name, err, tc.expectedErr)
			}
		} else if tc.expectedErr != nil {
			t.Fatalf("%s: expected error: %v", name, tc.expectedErr)
		}

		if err == nil {
			if len(newCAPem) == 0 || len(newCAKeyPem) == 0 || len(interim) == 0 || len(bundle) == 0 {
				t.Fatalf("%s: empty output data", name)
			}
		}

		newCACert, err := parsePemCert(newCAPem)
		if err != nil {
			t.Fatalf("%s: error parsing new CA %v", name, err)
		}

		newCAKey, err := parsePemKey(newCAKeyPem)
		if err != nil {
			t.Fatalf("%s: error parsing key: %v", name, err)
		}

		if !reflect.DeepEqual(newCACert.Subject, caCert.Subject) {
			t.Fatalf("%s: new and old certificate subjects do not match", name)
		}

		interimCACert, err := parsePemCert(interim)
		if err != nil {
			t.Fatalf("%s: error parsing interim CA %v", name, err)
		}

		if !reflect.DeepEqual(interimCACert.Subject, caCert.Subject) {
			t.Fatalf("%s: interim and old certificate subjects do not match", name)
		}

		// Verify bundle contains the expected number of certs
		bundleCerts, err := cert.ParseCertsPEM(bundle)
		if err != nil {
			t.Fatalf("%s: error parsing bundle certs %v", name, err)
		}

		if len(bundleCerts) != tc.bundleNum {
			t.Fatalf("%s: expected %d certs in bundle, got %d", name, tc.bundleNum, len(bundleCerts))
		}

		// Sign a cert with the old CA key and verify with the new bundle
		err = createAndVerifyTestCert(caCert, caKey, bundle, nil)
		if err != nil {
			t.Fatalf("%s: error verifying old serving cert: %v", name, err)
		}

		// Sign a cert with the new CA key and verify this cert with the old CA
		err = createAndVerifyTestCert(newCACert, newCAKey, tc.caCertPem, interim)
		if err != nil {
			t.Fatalf("%s: error verifying new serving cert: %v", name, err)
		}
	}
}

func createAndVerifyTestCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, trustBundle []byte, intermediate []byte) error {
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "cert",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now().Add(-1 * time.Second),
		NotAfter:           time.Now().Add(time.Duration(2) * 24 * time.Hour),
		SerialNumber:       big.NewInt(2),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	pubKey, _, err := cryptohelpers.NewKeyPair()
	if err != nil {
		return err
	}

	certDer, err := x509.CreateCertificate(crand.Reader, certTemplate, caCert, pubKey, caKey)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(trustBundle)
	if !ok {
		return errors.New("problem appending bundle to root pool")
	}
	var intermediatePool *x509.CertPool
	if len(intermediate) > 0 {
		intermediatePool = x509.NewCertPool()
		if !intermediatePool.AppendCertsFromPEM(intermediate) {
			return errors.New("problem appending bundle to intermediate pool")
		}
	}

	opts := x509.VerifyOptions{
		DNSName:       "",
		Intermediates: intermediatePool,
		Roots:         roots,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}
	return nil
}
