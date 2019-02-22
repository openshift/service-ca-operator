package operator

import (
	"fmt"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	scsclient "github.com/openshift/service-ca-operator/pkg/generated/clientset/versioned"
	scsinformers "github.com/openshift/service-ca-operator/pkg/generated/informers/externalversions"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
	"github.com/openshift/service-ca-operator/pkg/operator/v4_00_assets"
)

const resyncDuration = 10 * time.Minute

func RunOperator(ctx *controllercmd.ControllerContext) error {

	// This kube client uses protobuf, do not use it for CRs
	kubeClient, err := kubernetes.NewForConfig(ctx.ProtoKubeConfig)
	if err != nil {
		return err
	}
	scsClient, err := scsclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	operatorConfigClient, err := operatorv1client.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	dynamicClient, err := dynamic.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	configClient, err := configv1client.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	operatorConfigInformers := operatorv1informers.NewSharedInformerFactory(operatorConfigClient, resyncDuration)
	scsInformers := scsinformers.NewSharedInformerFactory(scsClient, resyncDuration)
	kubeInformersNamespaced := informers.NewFilteredSharedInformerFactory(kubeClient, resyncDuration, operatorclient.TargetNamespace, nil)
	v1helpers.EnsureOperatorConfigExists(
		dynamicClient,
		v4_00_assets.MustAsset("v4.0.0/service-ca-operator/operator-config.yaml"),
		operatorv1.GroupVersion.WithResource("servicecas"))

	operatorClient := &operatorclient.OperatorClient{
		Informers: operatorConfigInformers,
		Client:    operatorConfigClient.OperatorV1(),
	}

	clusterOperatorStatus := status.NewClusterOperatorStatusController(
		"service-ca",
		[]configv1.ObjectReference{
			{Group: "operator.openshift.io", Resource: "servicecas", Name: "cluster"},
			{Resource: "namespaces", Name: operatorclient.GlobalUserSpecifiedConfigNamespace},
			{Resource: "namespaces", Name: operatorclient.GlobalMachineSpecifiedConfigNamespace},
			{Resource: "namespaces", Name: operatorclient.OperatorNamespace},
			{Resource: "namespaces", Name: operatorclient.TargetNamespace},
		},
		configClient.ConfigV1(),
		operatorClient,
		status.NewVersionGetter(),
		ctx.EventRecorder,
	)

	operator := NewServiceCAOperator(
		scsInformers.Operator().V1().ServiceCAs(),
		kubeInformersNamespaced,
		scsClient.OperatorV1(),
		kubeClient.AppsV1(),
		kubeClient.CoreV1(),
		kubeClient.RbacV1(),
		ctx.EventRecorder,
	)

	operatorConfigInformers.Start(ctx.Done())
	kubeInformersNamespaced.Start(ctx.Done())

	go operator.Run(ctx.Done())

	go clusterOperatorStatus.Run(1, ctx.Done())

	<-ctx.Done()
	return fmt.Errorf("stopped")
}
