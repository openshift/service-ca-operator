package cabundleinjector

import (
	"context"
	"fmt"
	"io/ioutil"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/controller/factory"
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
	name               string
	sync               factory.SyncFunc
	informer           cache.SharedIndexInformer
	startInformers     startInformersFunc
	annotationsChecker factory.EventFilterFunc
	namespaced         bool
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
	injectionControllers := []factory.Controller{}
	for _, configConstructor := range configConstructors {
		ctlConfig := configConstructor(injectorConfig)

		queueFn := clusterObjToQueueKey
		if ctlConfig.namespaced {
			queueFn = namespacedObjToQueueKey
		}

		injectionControllers = append(injectionControllers,
			factory.New().
				WithSync(ctlConfig.sync).
				WithFilteredEventsInformersQueueKeyFunc(queueFn, ctlConfig.annotationsChecker, ctlConfig.informer).
				ToController(ctlConfig.name, controllerContext.EventRecorder),
		)

		// Start non-core informers
		if ctlConfig.startInformers != nil {
			ctlConfig.startInformers(stopChan)
		}
	}

	// Start core informers
	informers.Start(stopChan)

	// Start injector controllers once all informers have started
	for _, controllerRunner := range injectionControllers {
		go controllerRunner.Run(ctx, 5)
	}

	return nil
}

func annotationsChecker(supportedAnnotations ...string) factory.EventFilterFunc {
	return func(obj interface{}) bool {
		metaObj, ok := obj.(metav1.Object)

		// this block handles the case of a deleted object without panic-ing.  We try to use the last known status,
		// but it's only best effort.  if we're being deleted, there isn't a whole lot to be done.
		if !ok {
			tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
				return false
			}
			metaObj, ok = tombstone.Obj.(metav1.Object)
			if !ok {
				utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a metav1.Object %#v", obj))
				return false
			}
		}

		annotations := metaObj.GetAnnotations()
		for _, key := range supportedAnnotations {
			if strings.EqualFold(annotations[key], "true") {
				return true
			}
		}
		return false
	}
}

func namespacedObjToQueueKey(obj runtime.Object) string {
	metaObj := obj.(metav1.Object)
	return fmt.Sprintf("%s/%s", metaObj.GetNamespace(), metaObj.GetName())
}

func clusterObjToQueueKey(obj runtime.Object) string {
	metaObj := obj.(metav1.Object)
	return metaObj.GetName()
}

func namespacedObjectFromQueueKey(qKey string) (string, string) {
	nsName := strings.SplitN(qKey, "/", 2)
	// happilly panic on index errors if someone tried to use this on non-namespaced objects
	return nsName[0], nsName[1]
}
