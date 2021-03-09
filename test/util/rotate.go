package util

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
)

// CheckRotation validates that pre- and post-rotation servers and clients can communicate in a
// trusted fashion.
func CheckRotation(t *testing.T, dnsName string, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM []byte) {
	testCases := map[string]struct {
		certPEM   []byte
		keyPEM    []byte
		bundlePEM []byte
	}{
		"Pre-rotation": {
			certPEM:   oldCertPEM,
			keyPEM:    oldKeyPEM,
			bundlePEM: oldBundlePEM,
		},
		"Server rotated": {
			certPEM:   newCertPEM,
			keyPEM:    newKeyPEM,
			bundlePEM: oldBundlePEM,
		},
		"Client refreshed": {
			certPEM:   oldCertPEM,
			keyPEM:    oldKeyPEM,
			bundlePEM: newBundlePEM,
		},
		"Server rotated and client refreshed": {
			certPEM:   newCertPEM,
			keyPEM:    newKeyPEM,
			bundlePEM: newBundlePEM,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			checkClientTrust(t, testName, dnsName, tc.certPEM, tc.keyPEM, tc.bundlePEM)
		})
	}
}

// checkClientTrust verifies that a server configured with the provided cert and key will be
// trusted by a client with the given bundle.
func checkClientTrust(t *testing.T, testName, dnsName string, certPEM, keyPEM, bundlePEM []byte) {
	// Emulate how a service will consume the serving cert by writing
	// the cert and key to disk.
	certFile, err := ioutil.TempFile("", v1.TLSCertKey)
	if err != nil {
		t.Fatalf("error creating tmpfile for cert: %v", err)

	}
	defer func() {
		err := os.Remove(certFile.Name())
		if err != nil {
			t.Errorf("Failed to remove file %v", err)
		}
	}()
	_, err = certFile.Write(certPEM)
	if err != nil {
		t.Fatalf("Error writing cert to disk: %v", err)
	}

	keyFile, err := ioutil.TempFile("", v1.TLSPrivateKeyKey)
	if err != nil {
		t.Fatalf("error creating tmpfile for key: %v", err)

	}
	defer func() {
		err := os.Remove(keyFile.Name())
		if err != nil {
			t.Errorf("Failed to remove file %v", err)
		}
	}()
	_, err = keyFile.Write(keyPEM)
	if err != nil {
		t.Fatalf("Error writing key to disk: %v", err)
	}

	// The need to listen on a random port precludes the use of ListenAndServeTLS since that
	// method provides no way to determine the port that the server ends up listening
	// on. Creating a listener and using ServeTLS ensures a random port will be allocated
	// (by specifying ':0') and that the resulting port is discoverable via the listener's
	// Addr() method.
	listenerAddress := "127.0.0.1:0"
	ln, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() {
		_ = ln.Close()
	}()
	serverAddress := ln.Addr().String()
	serverPort := serverAddress[strings.LastIndex(serverAddress, ":")+1:]

	srv := http.Server{}
	// Start a server configured with the cert and key
	go func() {
		if err := srv.ServeTLS(ln, certFile.Name(), keyFile.Name()); err != nil && err != http.ErrServerClosed {
			t.Errorf("ServeTLS failed: %v", err)
		}
	}()
	defer func() {
		err := srv.Close()
		if err != nil {
			t.Fatalf("tls server close failed: %v", err)
		}
	}()

	// Make a client connection configured with the provided bundle.  A client is expected
	// to consume PEM content from a file, but there would be little value in writing the
	// bundle to disk and reading it back.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(bundlePEM)
	dialer := &net.Dialer{
		Timeout: 60 * time.Second,
	}
	client := http.Client{
		Transport: &http.Transport{
			// The server being targeted is serving on 127.0.0.1 which is not specified in
			// the serving cert. Override the DialContext address to always use 127.0.0.1
			// when the service dns name is used to ensure that cert validation can succeed.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = "127.0.0.1" + addr[strings.LastIndex(addr, ":"):]
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
				// Ensure the server name matches the name used in the request.
				ServerName: dnsName,
			},
		},
		Timeout: 60 * time.Second,
	}
	clientAddress := fmt.Sprintf("https://%s:%s", dnsName, serverPort)
	_, err = client.Get(clientAddress)
	if err != nil {
		t.Fatalf("Failed to receive output: %v\ncertPEM: %s\nkeyPEM: %s\nbundlePEM: %s", err,
			base64.StdEncoding.EncodeToString(certPEM),
			base64.StdEncoding.EncodeToString(keyPEM),
			base64.StdEncoding.EncodeToString(bundlePEM),
		)
	}
	// No error indicates that validation was successful
}

// CheckData verifies that the new map contains the same keys as the
// old and that the values have changed.
func CheckData(oldData, newData map[string][]byte) error {
	if len(oldData) != len(newData) {
		return fmt.Errorf("expected data size %d, got %d", len(oldData), len(newData))
	}
	for key, oldValue := range oldData {
		newValue, ok := newData[key]
		if !ok {
			return fmt.Errorf("key %q is missing", key)
		}
		if bytes.Equal(oldValue, newValue) {
			return fmt.Errorf("value for key %q has not changed", key)
		}
	}
	return nil
}
