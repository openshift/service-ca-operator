package starter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"

	webhookinformer "k8s.io/client-go/informers"
	webhookclient "k8s.io/client-go/kubernetes"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/webhookcabundle/controller"
)

func StartWebhookCABundleInjector(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// TODO(marun) Allow this value to be supplied via argument
	caBundleFile := "/var/run/configmaps/signing-cabundle/ca-bundle.crt"

	caBundleContent, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		return err
	}
	encodedCaBundleContent := []byte(base64.StdEncoding.EncodeToString(caBundleContent))

	webhookClient, err := webhookclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	webhookInformers := webhookinformer.NewSharedInformerFactory(webhookClient, 2*time.Minute)

	servingCertUpdateController := controller.NewWebhookCABundleInjector(
		webhookInformers.Admissionregistration().V1beta1().ValidatingWebhookConfigurations(),
		webhookClient.AdmissionregistrationV1beta1(),
		encodedCaBundleContent,
	)

	stopChan := ctx.Done()

	webhookInformers.Start(stopChan)

	go servingCertUpdateController.Run(5, stopChan)

	<-stopChan

	return fmt.Errorf("stopped")
}
