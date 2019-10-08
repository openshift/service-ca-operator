package starter

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/klog"

	scsv1alpha1 "github.com/openshift/api/servicecertsigner/v1alpha1"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
)

func StartServiceServingCertSigner(ctx *controllercmd.ControllerContext) error {

	config := &scsv1alpha1.ServiceServingCertSignerConfig{}
	if ctx.ComponentConfig != nil {
		// make a copy we can mutate
		configCopy := ctx.ComponentConfig.DeepCopy()
		// force the config to our version to read it
		configCopy.SetGroupVersionKind(scsv1alpha1.GroupVersion.WithKind("ServiceServingCertSignerConfig"))
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(configCopy.Object, config); err != nil {
			return err
		}
	}
	ca, err := crypto.GetCA(config.Signer.CertFile, config.Signer.KeyFile, "")
	if err != nil {
		return err
	}

	if len(config.IntermediateCertFile) == 0 {
		return errors.New("the filename for the intermediate certificate was not provided")
	}
	// An intermediate cert will only be present after a successful CA rotation.
	intermediateCACert, err := readIntermediateCACert(config.IntermediateCertFile)
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	servingCertController := controller.NewServiceServingCertController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		ca,
		intermediateCACert,
		// TODO this needs to be configurable
		"cluster.local",
	)
	servingCertUpdateController := controller.NewServiceServingCertUpdateController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		ca,
		intermediateCACert,
		// TODO this needs to be configurable
		"cluster.local",
	)

	kubeInformers.Start(ctx.Done())

	go servingCertController.Run(5, ctx.Done())
	go servingCertUpdateController.Run(5, ctx.Done())

	<-ctx.Done()

	return fmt.Errorf("stopped")
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
