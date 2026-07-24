package configobservation

import (
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	libgoapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// Listers combines the required listers for config observation
type Listers struct {
	apiServerLister configlistersv1.APIServerLister
	resourceSyncer  resourcesynccontroller.ResourceSyncer
	cacheSyncs      []cache.InformerSynced
}

// APIServerLister returns the APIServer lister
func (l Listers) APIServerLister() configlistersv1.APIServerLister {
	return l.apiServerLister
}

// ResourceSyncer returns the resource syncer
func (l Listers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.resourceSyncer
}

// PreRunHasSynced returns the cache sync functions
func (l Listers) PreRunHasSynced() []cache.InformerSynced {
	return l.cacheSyncs
}

// NewConfigObserverController creates a config observer controller for service-ca-operator
func NewConfigObserverController(
	operatorClient v1helpers.OperatorClient,
	configInformer configinformers.SharedInformerFactory,
	resourceSyncer resourcesynccontroller.ResourceSyncer,
	eventRecorder events.Recorder,
) factory.Controller {
	informers := []factory.Informer{
		operatorClient.Informer(),
		configInformer.Config().V1().APIServers().Informer(),
	}

	return configobserver.NewConfigObserver(
		"service-ca",
		operatorClient,
		eventRecorder,
		Listers{
			apiServerLister: configInformer.Config().V1().APIServers().Lister(),
			resourceSyncer:  resourceSyncer,
			cacheSyncs: []cache.InformerSynced{
				operatorClient.Informer().HasSynced,
				configInformer.Config().V1().APIServers().Informer().HasSynced,
			},
		},
		informers,
		libgoapiserver.ObserveTLSSecurityProfile,
	)
}
