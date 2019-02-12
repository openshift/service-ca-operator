package starter

import (
	"fmt"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	servicecertsignerv1alpha1 "github.com/openshift/api/servicecertsigner/v1alpha1"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/service-ca-operator/pkg/controller/servingcert/controller"
)

func ToStartFunc(config *servicecertsignerv1alpha1.ServiceServingCertSignerConfig) (controllercmd.StartFunc, error) {
	ca, err := crypto.GetCA(config.Signer.CertFile, config.Signer.KeyFile, "")
	if err != nil {
		return nil, err
	}

	opts := &servingCertOptions{ca: ca}
	return opts.runServingCert, nil
}

type servingCertOptions struct {
	ca *crypto.CA
}

func (o *servingCertOptions) runServingCert(ctx *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	servingCertController := controller.NewServiceServingCertController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		kubeClient.CoreV1(),
		o.ca,
		// TODO this needs to be configurable
		"cluster.local",
	)
	servingCertUpdateController := controller.NewServiceServingCertUpdateController(
		kubeInformers.Core().V1().Services(),
		kubeInformers.Core().V1().Secrets(),
		kubeClient.CoreV1(),
		o.ca,
		// TODO this needs to be configurable
		"cluster.local",
	)

	kubeInformers.Start(ctx.Context.Done())

	go servingCertController.Run(5, ctx.Context.Done())
	go servingCertUpdateController.Run(5, ctx.Context.Done())

	<-ctx.Context.Done()

	return fmt.Errorf("stopped")
}
