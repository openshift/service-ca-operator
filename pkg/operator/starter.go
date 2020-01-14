package operator

import (
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"

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

var targetDeploymentNames = sets.NewString(
	api.SignerControllerDeploymentName,
	api.APIServiceInjectorDeploymentName,
	api.ConfigMapInjectorDeploymentName,
)

func RunOperator(ctx *controllercmd.ControllerContext) error {

	// This kube client uses protobuf, do not use it for CRs
	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}
	operatorConfigClient, err := operatorv1client.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	configClient, err := configv1client.NewForConfig(ctx.KubeConfig)
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
		ctx.EventRecorder,
	)

	resourceSyncController := resourcesynccontroller.NewResourceSyncController(
		operatorClient,
		kubeInformersForNamespaces,
		v1helpers.CachedSecretGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		v1helpers.CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformersForNamespaces),
		ctx.EventRecorder,
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
		ctx.EventRecorder,
	)

	operatorConfigInformers.Start(ctx.Done())
	configInformers.Start(ctx.Done())
	kubeInformersNamespaced.Start(ctx.Done())
	kubeInformersForNamespaces.Start(ctx.Done())

	cleanupUnifiedDeployment(kubeClient, ctx.Done())

	go operator.Run(ctx.Done())
	go clusterOperatorStatus.Run(1, ctx.Done())
	go resourceSyncController.Run(1, ctx.Done())

	<-ctx.Done()
	return fmt.Errorf("stopped")
}

// cleanupUnifiedDeployment removes resources associated with the unified service ca
// controller deployment created by the 4.4 operator. This is intended to remove the
// possibility of contention between the 4.4 deployment and the multiple deployments
// managed by the 4.3 operator in the event of a downgrade from 4.4 to 4.3.
func cleanupUnifiedDeployment(kubeClient *kubernetes.Clientset, stopCh <-chan struct{}) error {
	controllerName := "service-ca"
	namespace := operatorclient.TargetNamespace
	configName := fmt.Sprintf("%s-config", controllerName)
	lockName := fmt.Sprintf("%s-lock", controllerName)
	saName := fmt.Sprintf("%s-sa", controllerName)
	roleAndBindingName := fmt.Sprintf("system:openshift:controller:%s", controllerName)
	delOpts := &metav1.DeleteOptions{}
	deletionFuncs := []func() error{
		// Delete deployment openshift-service-ca/<controller-name>
		func() error { return kubeClient.AppsV1().Deployments(namespace).Delete(controllerName, delOpts) },
		// Delete ClusterRole system:openshift:controller:{controller name}
		func() error { return kubeClient.RbacV1().ClusterRoles().Delete(roleAndBindingName, delOpts) },
		// Delete ClusterRole system:openshift:controller:{controller name}
		func() error { return kubeClient.RbacV1().ClusterRoles().Delete(roleAndBindingName, delOpts) },
		// Delete ClusterRoleBinding system:openshift:controller:{controller name}
		func() error { return kubeClient.RbacV1().ClusterRoleBindings().Delete(roleAndBindingName, delOpts) },
		// Delete ConfigMap openshift-service-ca/{controller name}-config
		func() error { return kubeClient.CoreV1().ConfigMaps(namespace).Delete(configName, delOpts) },
		// Delete ConfigMap openshift-service-ca/{controller name}-lock
		func() error { return kubeClient.CoreV1().ConfigMaps(namespace).Delete(lockName, delOpts) },
		// Delete Role openshift-service-ca/system:openshift:controller:{controller name}
		func() error { return kubeClient.RbacV1().Roles(namespace).Delete(roleAndBindingName, delOpts) },
		// Delete RoleBinding openshift-service-ca/system:openshift:controller:{controller name}
		func() error { return kubeClient.RbacV1().RoleBindings(namespace).Delete(roleAndBindingName, delOpts) },
		// Delete ServiceAccount openshift-service-ca/{controller name}-sa
		func() error { return kubeClient.CoreV1().ServiceAccounts(namespace).Delete(saName, delOpts) },
	}
	go wait.Until(func() {
		klog.V(4).Infof("attempting removal of the unified service ca controller created by the 4.4 operator in namespace %q", operatorclient.TargetNamespace)
		for _, deletionFunc := range deletionFuncs {
			err := deletionFunc()
			if apierrors.IsNotFound(err) {
				// Already removed
				continue
			}
			if err != nil {
				klog.Errorf("Error deleting 4.4 resource: %v", err)
			}
		}
	}, 20*time.Minute, stopCh)
	return nil
}
