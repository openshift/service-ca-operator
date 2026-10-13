package starter

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	configeversionedclient "github.com/openshift/client-go/config/clientset/versioned"
	configexternalinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
)

func StartServiceServingCertSigner(ctx context.Context, controllerContext *controllercmd.ControllerContext, enabledFeatureGates map[string]bool) error {
	// TODO(marun) Allow the following values to be supplied via argument
	certFile := "/var/run/secrets/signing-key/tls.crt"
	keyFile := "/var/run/secrets/signing-key/tls.key"
	intermediateCertFile := "/var/run/secrets/signing-key/intermediate-ca.crt"

	ca, err := crypto.GetCA(certFile, keyFile, "")
	if err != nil {
		return err
	}

	// An intermediate cert will only be present after a successful CA rotation.
	intermediateCACert, err := readIntermediateCACert(intermediateCertFile)
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	// Feature gates are passed to the controller via CLI args from the
	// operator process, rather than being detected at runtime via
	// FeatureGate/ClusterVersion informers. This is necessary because
	// MicroShift does not have the ClusterVersion and FeatureGate CRDs,
	// and runtime detection would cause the controller to crash.
	configurablePKIEnabled := enabledFeatureGates["ConfigurablePKI"]

	// Only create config informers when ConfigurablePKI is enabled, since
	// MicroShift may not have the required config CRDs.
	var configInformers configexternalinformers.SharedInformerFactory
	if configurablePKIEnabled {
		configClient, err := configeversionedclient.NewForConfig(controllerContext.KubeConfig)
		if err != nil {
			return fmt.Errorf("failed to create config client: %w", err)
		}
		configInformers = configexternalinformers.NewSharedInformerFactory(configClient, 10*time.Minute)
	}

	minTimeLeftForCert := time.Hour
	certificateLifetime := 2 * 365 * 24 * time.Hour
	if enabledFeatureGates["ShortCertRotation"] {
		minTimeLeftForCert = time.Hour
		certificateLifetime = time.Hour * 2
	}
	klog.Infof("Setting certificate lifetime to %v, refresh certificate at %v", certificateLifetime, minTimeLeftForCert)

	servingCertController := controller.NewServiceServingCertController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		configInformers,
		configurablePKIEnabled,
		ca,
		intermediateCACert,
		// TODO this needs to be configurable
		"cluster.local",
		controllerContext.EventRecorder,
		certificateLifetime,
	)
	servingCertUpdateController := controller.NewServiceServingCertUpdateController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		configInformers,
		configurablePKIEnabled,
		ca,
		intermediateCACert,
		// TODO this needs to be configurable
		"cluster.local",
		controllerContext.EventRecorder,
		minTimeLeftForCert,
		certificateLifetime,
	)

	kubeInformers.Start(ctx.Done())
	if configInformers != nil {
		configInformers.Start(ctx.Done())
	}

	go servingCertController.Run(ctx, 5)
	go servingCertUpdateController.Run(ctx, 5)

	return nil
}

// readIntermediateCACert attempts to read an intermediate certificate
// from the provided filename.
//
// If the file is missing, it is assumed that the service CA has not
// yet been rotated. An intermediate certificate is only required to
// bridge trust between the current and previous CA, but a new cluster
// will not have a previous CA.
func readIntermediateCACert(filename string) (*x509.Certificate, error) {
	certsPEMBlock, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		klog.V(4).Infof("%q does not exist which indicates that an intermediate certificate was not specified", filename)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	certs, err := cert.ParseCertsPEM(certsPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("error parsing intermediate cert from %s: %s", filename, err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("expected 1 intermediate cert, got %d", len(certs))
	}
	return certs[0], nil
}
