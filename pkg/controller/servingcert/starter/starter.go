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

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
)

func StartServiceServingCertSigner(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// TODO(marun) Allow the following values to be supplied via argument
	certFile := "/var/run/secrets/signing-key/tls.crt"
	keyFile := "/var/run/secrets/signing-key/tls.key"
	intermediateCertFile := "/var/run/secrets/signing-key/intermediate-ca.crt"
	// TODO this needs to be configurable
	dnsSuffix := "cluster.local"

	ca, err := crypto.GetCA(certFile, keyFile, "")
	if err != nil {
		return err
	}
	// An intermediate cert will only be present after a successful CA rotation.
	intermediateCACert, err := readIntermediateCACert(intermediateCertFile)
	if err != nil {
		return err
	}
	servingCA := controller.NewServingCA(ca, intermediateCACert, dnsSuffix)

	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	serviceServingCertController := controller.NewServiceServingCertController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		servingCA,
		controllerContext.EventRecorder,
	)
	serviceServingCertUpdateController := controller.NewServiceServingCertUpdateController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		servingCA,
		controllerContext.EventRecorder,
	)
	statefulSetServingCertController := controller.NewStatefulSetServingCertController(
		kubeInformers.Apps().V1().StatefulSets(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.AppsV1(),
		kubeClient.CoreV1(),
		servingCA,
		controllerContext.EventRecorder,
	)
	statefulSetServingCertUpdateController := controller.NewStatefulSetServingCertUpdateController(
		kubeInformers.Apps().V1().StatefulSets(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		servingCA,
		controllerContext.EventRecorder,
	)

	stopChan := ctx.Done()
	kubeInformers.Start(stopChan)

	go serviceServingCertController.Run(ctx, 5)
	go serviceServingCertUpdateController.Run(ctx, 5)
	go statefulSetServingCertController.Run(ctx, 5)
	go statefulSetServingCertUpdateController.Run(ctx, 5)

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
