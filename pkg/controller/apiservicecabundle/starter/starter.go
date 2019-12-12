package starter

import (
	"context"
	"io/ioutil"
	"time"

	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceinformer "k8s.io/kube-aggregator/pkg/client/informers/externalversions"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/apiservicecabundle/controller"
)

func StartAPIServiceCABundleInjector(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// TODO(marun) Allow this value to be supplied via argument
	caBundleFile := "/var/run/configmaps/signing-cabundle/ca-bundle.crt"

	caBundleContent, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		return err
	}

	apiServiceClient, err := apiserviceclient.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	apiServiceInformers := apiserviceinformer.NewSharedInformerFactory(apiServiceClient, 2*time.Minute)

	servingCertUpdateController := controller.NewAPIServiceCABundleInjector(
		apiServiceInformers.Apiregistration().V1().APIServices(),
		apiServiceClient.ApiregistrationV1(),
		caBundleContent,
	)

	stopChan := ctx.Done()

	apiServiceInformers.Start(stopChan)

	go servingCertUpdateController.Run(5, stopChan)

	return nil
}
