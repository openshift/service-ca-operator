package operator

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	features "github.com/openshift/api/features"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/loglevel"
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
		Clock:     controllerContext.Clock,
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
		controllerContext.Clock,
	)

	resourceSyncController := resourcesynccontroller.NewResourceSyncController(
		"resource-sync",
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

	operatorLogLevelController := loglevel.NewClusterOperatorLoggingController(
		operatorClient,
		controllerContext.EventRecorder,
	)

	klog.Infof("Fetching FeatureGates")
	stopChan := ctx.Done()
	featureGateAccessor := featuregates.NewFeatureGateAccess(
		status.VersionForOperatorFromEnv(), "0.0.1-snapshot",
		configInformers.Config().V1().ClusterVersions(), configInformers.Config().V1().FeatureGates(),
		controllerContext.EventRecorder,
	)
	go featureGateAccessor.Run(ctx)
	go configInformers.Start(stopChan)

	var featureGates featuregates.FeatureGate
	select {
	case <-featureGateAccessor.InitialFeatureGatesObserved():
		featureGates, _ = featureGateAccessor.CurrentFeatureGates()
	case <-time.After(1 * time.Minute):
		klog.Errorf("timed out waiting for FeatureGate detection")
		return fmt.Errorf("timed out waiting for FeatureGate detection")
	}

	// The minimum remaining duration of the service CA needs to exceeds the maximum
	// supported upgrade interval (currently 12 months). A duration of 26 months
	// (rotated at 13 months) ensures that an upgrade will occur after automated
	// rotation and before the expiry of the pre-rotation CA. Since an upgrade restarts
	// all services, those services will always be using valid material.
	//
	// Example timeline using a 26 month service CA duration:
	//
	// - T+0m  - Cluster installed with new CA or existing CA is rotated (CA-1)
	// - T+12m - Cluster is upgraded and all pods are restarted
	// - T+13m - Automated rotation replaces CA-1 with CA-2 when CA-1 duration < 13m
	// - T+24m - Cluster is upgraded and all pods are restarted
	// - T+26m - CA-1 expires. No impact because of the restart at time of upgrade
	//
	signingCertificateLifetime := 790 * 24 * time.Hour

	// The minimum duration that a CA should be trusted is approximately half
	// the default signing certificate lifetime. If a signing CA is valid for
	// less than this duration, it is due for rotation. An intermediate
	// certificate created by rotation (to ensure that the previous CA remains
	// trusted) should be valid for at least this long.
	minimumTrustDuration := 395 * 24 * time.Hour

	shortCertRotationEnabled := false

	if featureGates.Enabled(features.FeatureShortCertRotation) {
		minimumTrustDuration = time.Hour + 15*time.Minute
		signingCertificateLifetime = time.Hour*2 + 30*time.Minute
		shortCertRotationEnabled = true
	}
	klog.Infof("Setting signing certificate lifetime to %v, minimum trust duration to %v", signingCertificateLifetime, minimumTrustDuration)

	operator := NewServiceCAOperator(
		operatorClient,
		kubeInformersNamespaced,
		configInformers,
		kubeClient.AppsV1(),
		kubeClient.CoreV1(),
		kubeClient.RbacV1(),
		versionGetter,
		controllerContext.EventRecorder,
		minimumTrustDuration,
		signingCertificateLifetime,
		shortCertRotationEnabled,
	)

	for _, informerStarter := range []func(<-chan struct{}){
		operatorConfigInformers.Start,
		kubeInformersNamespaced.Start,
		kubeInformersForNamespaces.Start,
		configInformers.Start,
	} {
		informerStarter(stopChan)
	}

	for _, controllerRunner := range []func(ctx context.Context, workers int){
		operator.Run,
		operatorLogLevelController.Run,
		clusterOperatorStatus.Run,
		resourceSyncController.Run,
	} {
		go controllerRunner(ctx, 1)
	}

	<-stopChan
	return nil
}
