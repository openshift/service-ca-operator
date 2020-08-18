package operator

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

const (
	resyncDuration         = 10 * time.Minute
	clusterOperatorName    = "service-ca"
	operatorVersionEnvName = "OPERATOR_IMAGE_VERSION"
)

var targetDeploymentNames = sets.NewString(api.ServiceCADeploymentName)

func RunOperator(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {

	// This kube client uses protobuf, do not use it for CRs
	kubeClient, err := kubernetes.NewForConfig(controllerContext.ProtoKubeConfig)
	if err != nil {
		return err
	}
	operatorConfigClient, err := operatorv1client.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}
	configClient, err := configv1client.NewForConfig(controllerContext.KubeConfig)
	if err != nil {
		return err
	}
	configInformers := configv1informers.NewSharedInformerFactory(configClient, resyncDuration)
	operatorConfigInformers := operatorv1informers.NewSharedInformerFactory(operatorConfigClient, resyncDuration)

	kubeInformersNamespaced := informers.NewFilteredSharedInformerFactory(kubeClient, resyncDuration, operatorclient.TargetNamespace, nil)
	kubeInformersForNamespaces := v1helpers.NewKubeInformersForNamespaces(kubeClient,
		"",
		operatorclient.GlobalUserSpecifiedConfigNamespace,
		operatorclient.GlobalMachineSpecifiedConfigNamespace,
		operatorclient.OperatorNamespace,
		operatorclient.TargetNamespace,
	)

	operatorClient := &operatorclient.OperatorClient{
		Informers: operatorConfigInformers,
		Client:    operatorConfigClient.OperatorV1(),
	}

	versionGetter := status.NewVersionGetter()

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		clusterOperatorName,
		[]configv1.ObjectReference{
			{Group: operatorv1.GroupName, Resource: "servicecas", Name: api.OperatorConfigInstanceName},
			{Resource: "namespaces", Name: operatorclient.GlobalUserSpecifiedConfigNamespace},
			{Resource: "namespaces", Name: operatorclient.GlobalMachineSpecifiedConfigNamespace},
			{Resource: "namespaces", Name: operatorclient.OperatorNamespace},
			{Resource: "namespaces", Name: operatorclient.TargetNamespace},
		},
		configClient.ConfigV1(),
		configInformers.Config().V1().ClusterOperators(),
		operatorClient,
		versionGetter,
		controllerContext.EventRecorder,
	)

	resourceSyncController := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		controllerContext.EventRecorder,
	)
	if err := resourceSyncController.SyncConfigMap(
		resourcesynccontroller.ResourceLocation{Namespace: operatorclient.GlobalMachineSpecifiedConfigNamespace, Name: clusterOperatorName},
		resourcesynccontroller.ResourceLocation{Namespace: operatorclient.TargetNamespace, Name: api.SigningCABundleConfigMapName},
	); err != nil {
		return err
	}

	operator := NewServiceCAOperator(
		operatorClient,
		kubeInformersNamespaced,
		kubeClient.AppsV1(),
		kubeClient.CoreV1(),
		kubeClient.RbacV1(),
		versionGetter,
		controllerContext.EventRecorder,
	)

	stopChan := ctx.Done()

	operatorConfigInformers.Start(stopChan)
	configInformers.Start(stopChan)
	kubeInformersNamespaced.Start(stopChan)
	kubeInformersForNamespaces.Start(stopChan)

	// Poll every minute to ensure removal of 4.3 deployments that were replaced in 4.4
	// with a unified deployment.
	//
	// This code can be removed in 4.5 since downgrade to 4.3 will no longer be possible.
	deployClient := kubeClient.AppsV1().Deployments(operatorclient.TargetNamespace)
	go wait.Until(func() {
		// List rather than blindly deleting so that there are max 1 request/minute
		// instead of 3 (one for each 4.3 deployment).
		deploys, err := deployClient.List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			klog.Warningf("Failed to list deployments when searching for 4.3 deployments to remove: %v", err)
		}
		if deploys == nil {
			return
		}
		for _, deploy := range deploys.Items {
			if api.IndependentDeploymentNames.Has(deploy.Name) {
				err := deployClient.Delete(context.TODO(), deploy.Name, metav1.DeleteOptions{})
				if err != nil {
					klog.Warningf("Failed to delete 4.3 deployment: %v", err)
				}
			}
		}
	}, 1*time.Minute, ctx.Done())

	go operator.Run(stopChan)
	go clusterOperatorStatus.Run(ctx, 1)
	go resourceSyncController.Run(ctx, 1)

	<-stopChan
	return fmt.Errorf("stopped")
}
