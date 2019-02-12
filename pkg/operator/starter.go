package operator

import (
	"fmt"
	"time"

	//"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	//"k8s.io/client-go/tools/cache"
	"github.com/openshift/library-go/pkg/controller/controllercmd"

	//servicecav1 "github.com/openshift/service-ca-operator/pkg/apis/serviceca/v1"
	scsclient "github.com/openshift/service-ca-operator/pkg/generated/clientset/versioned"
	scsinformers "github.com/openshift/service-ca-operator/pkg/generated/informers/externalversions"
)

const (
	globalConfigName = "cluster"

	// TODO unpause when ready
	defaultOperatorConfig = `
apiVersion: operator.openshift.io/v1
kind: ServiceCA
metadata:
  name: ` + globalConfigName + `
spec:
  managementState: Paused
`
)

func RunOperator(ctx *controllercmd.ControllerContext) error {
	kubeClient, err := kubernetes.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}
	scsClient, err := scsclient.NewForConfig(ctx.KubeConfig)
	if err != nil {
		return err
	}

	operatorInformers := scsinformers.NewSharedInformerFactory(scsClient, 10*time.Minute)
	kubeInformersNamespaced := informers.NewFilteredSharedInformerFactory(kubeClient, 10*time.Minute, targetNamespaceName, nil)

	// TODO: Use this
	//v1alpha1helpers.EnsureOperatorConfigExists(
	//	dynamicClient,
	//	[]byte(defaultOperatorConfig),
	//	servicecav1.GroupVersion.WithResource("serviceca"),
	//	func() string { return "" },
	//)

	// TODO: Uncomment when we get a library bump and use v1 for status.
	// clusterOperatorStatus := status.NewClusterOperatorStatusController(
	//	"openshift-service-ca-operator",
	//	"openshift-service-ca-operator",
	//	dynamicClient,
	//	&operatorStatusProvider{informers: operatorInformers},
	//)

	operator := NewServiceCertSignerOperator(
		operatorInformers.Operator().V1().ServiceCAs(),
		kubeInformersNamespaced,
		scsClient.OperatorV1(),
		kubeClient.AppsV1(),
		kubeClient.CoreV1(),
		kubeClient.RbacV1(),
		ctx.EventRecorder,
	)

	operatorInformers.Start(ctx.Context.Done())
	kubeInformersNamespaced.Start(ctx.Context.Done())

	go operator.Run(ctx.Context.Done())
	// TODO: Uncomment when we get a library bump and use v1 for status.
	//go clusterOperatorStatus.Run(1, stopCh)

	<-ctx.Context.Done()
	return fmt.Errorf("stopped")
}

// TODO: Uncomment when we get a library bump and use v1 for status.
//type operatorStatusProvider struct {
//	informers scsinformers.SharedInformerFactory
//}
//
//func (p *operatorStatusProvider) Informer() cache.SharedIndexInformer {
//	return p.informers.Operator().V1().ServiceCAs().Informer()
//}
//
//func (p *operatorStatusProvider) CurrentStatus() (servicecav1.OperatorStatus, error) {
//	instance, err := p.informers.Operator().V1().ServiceCAs().Lister().Get(globalConfigName)
//	if err != nil {
//		return servicecav1.OperatorStatus{}, err
//	}
//	return instance.Status.OperatorStatus, nil
//}
