package cabundleinjector

import (
	"context"
	"io/ioutil"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/operator-boilerplate-legacy/pkg/controller"
)

type caBundleInjectorConfig struct {
	config        *rest.Config
	defaultResync time.Duration
	caBundle      []byte
	kubeClient    *kubernetes.Clientset
	kubeInformers kubeinformers.SharedInformerFactory
}

type startInformersFunc func(stopChan <-chan struct{})

type controllerConfig struct {
	name                 string
	keySyncer            controller.KeySyncer
	informerGetter       controller.InformerGetter
	startInformers       startInformersFunc
	supportedAnnotations []string
}

type configBuilderFunc func(config *caBundleInjectorConfig) controllerConfig

func StartCABundleInjector(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	// TODO(marun) Detect and respond to changes in this path rather than
	// depending on the operator for redeployment
	caBundleFile := "/var/run/configmaps/signing-cabundle/ca-bundle.crt"

	caBundleContent, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		return err
	}

	client := kubernetes.NewForConfigOrDie(controllerContext.ProtoKubeConfig)
	defaultResync := 20 * time.Minute
	informers := kubeinformers.NewSharedInformerFactory(client, defaultResync)
	injectorConfig := &caBundleInjectorConfig{
		config:        controllerContext.ProtoKubeConfig,
		defaultResync: defaultResync,
		caBundle:      caBundleContent,
		kubeClient:    client,
		kubeInformers: informers,
	}

	stopChan := ctx.Done()

	configConstructors := []configBuilderFunc{
		newAPIServiceInjectorConfig,
		newConfigMapInjectorConfig,
		newCRDInjectorConfig,
		newMutatingWebhookInjectorConfig,
		newValidatingWebhookInjectorConfig,
	}
	controllerRunners := []controller.Runner{}
	for _, configConstructor := range configConstructors {
		ctlConfig := configConstructor(injectorConfig)
		controllerRunner := controller.New(ctlConfig.name, ctlConfig.keySyncer,
			controller.WithInformer(ctlConfig.informerGetter, controller.FilterFuncs{
				AddFunc: func(obj v1.Object) bool {
					return hasSupportedInjectionAnnotation(obj, ctlConfig.supportedAnnotations)
				},
				UpdateFunc: func(old, cur v1.Object) bool {
					return hasSupportedInjectionAnnotation(cur, ctlConfig.supportedAnnotations)
				},
			}),
		)
		controllerRunners = append(controllerRunners, controllerRunner)

		// Start non-core informers
		if ctlConfig.startInformers != nil {
			ctlConfig.startInformers(stopChan)
		}
	}

	// Start core informers
	informers.Start(stopChan)

	// Start injector controllers once all informers have started
	for _, controllerRunner := range controllerRunners {
		go controllerRunner.Run(5, stopChan)
	}

	return nil
}

func hasSupportedInjectionAnnotation(obj v1.Object, supportedAnnotations []string) bool {
	annotations := obj.GetAnnotations()
	for _, key := range supportedAnnotations {
		if strings.EqualFold(annotations[key], "true") {
			return true
		}
	}
	return false
}
