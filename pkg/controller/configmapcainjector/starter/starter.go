package starter

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/configmapcainjector/controller"
)

func StartConfigMapCABundleInjector(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// TODO(marun) Allow this value to be supplied via argument
	caBundleFile := "/var/run/configmaps/signing-cabundle/ca-bundle.crt"

	ca, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		return err
	}
	// Verify that there is at least one cert in the bundle file
	block, _ := pem.Decode(ca)
	if block == nil {
		return fmt.Errorf("failed to parse CA bundle file as pem")
	}
	if _, err = x509.ParseCertificate(block.Bytes); err != nil {
		return err
	}
	caBundle := string(ca)

	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	configMapInjectorController := controller.NewConfigMapCABundleInjectionController(
		kubeInformers.Core().V1().ConfigMaps(),
		kubeClient.CoreV1(),
		caBundle,
	)

	stopChan := ctx.Done()

	kubeInformers.Start(stopChan)

	go configMapInjectorController.Run(5, stopChan)

	return nil
}
