package starter

import (
	"fmt"
	"io/ioutil"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	scsv1alpha1 "github.com/openshift/api/servicecertsigner/v1alpha1"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/webhookconfigurationcabundle/controller"
)

func StartWebhookConfigurationCABundleInjector(ctx *controllercmd.ControllerContext) error {
	// TODO(spangenberg): Adapt to webhookconfiguration - START
	config := &scsv1alpha1.ConfigMapCABundleInjectorConfig{}
	if ctx.ComponentConfig != nil {
		// make a copy we can mutate
		configCopy := ctx.ComponentConfig.DeepCopy()
		// force the config to our version to read it
		configCopy.SetGroupVersionKind(scsv1alpha1.GroupVersion.WithKind("ConfigMapCABundleInjectorConfig"))
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(configCopy.Object, config); err != nil {
			return err
		}
	}
	// TODO(spangenberg): Adapt to webhookconfiguration - END

	if len(config.CABundleFile) == 0 {
		return fmt.Errorf("no ca bundle provided")
	}

	caBundle, err := ioutil.ReadFile(config.CABundleFile)
	if err != nil {
		return err
	}

	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}
	kubeInformers := informers.NewSharedInformerFactory(kubeClient, 20*time.Minute)

	webhookConfigurationCABundleInjectionController := controller.NewWebhookConfigurationCABundleInjectionController(
		kubeInformers.Admissionregistration().V1beta1().MutatingWebhookConfigurations(),
		kubeInformers.Admissionregistration().V1beta1().ValidatingWebhookConfigurations(),
		kubeClient.AdmissionregistrationV1beta1(),
		caBundle,
	)

	kubeInformers.Start(ctx.Done())

	go webhookConfigurationCABundleInjectionController.Run(5, ctx.Done())

	<-ctx.Done()

	return fmt.Errorf("stopped")
}
