package operator

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclientv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

type serviceCAOperator struct {
	operatorClient       *operatorclient.OperatorClient
	operatorConfigLister operatorv1listers.ServiceCALister

	appsv1Client  appsclientv1.AppsV1Interface
	corev1Client  coreclientv1.CoreV1Interface
	rbacv1Client  rbacclientv1.RbacV1Interface
	versionGetter status.VersionGetter
	eventRecorder events.Recorder
}

func NewServiceCAOperator(
	operatorClient *operatorclient.OperatorClient,

	namespacedKubeInformers informers.SharedInformerFactory,
	appsv1Client appsclientv1.AppsV1Interface,
	corev1Client coreclientv1.CoreV1Interface,
	rbacv1Client rbacclientv1.RbacV1Interface,
	versionGetter status.VersionGetter,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &serviceCAOperator{
		operatorClient:       operatorClient,
		operatorConfigLister: operatorClient.Informers.Operator().V1().ServiceCAs().Lister(),

		appsv1Client:  appsv1Client,
		corev1Client:  corev1Client,
		rbacv1Client:  rbacv1Client,
		versionGetter: versionGetter,
		eventRecorder: eventRecorder,
	}

	return factory.New().WithInformers(
		namespacedKubeInformers.Core().V1().ConfigMaps().Informer(),
		namespacedKubeInformers.Core().V1().ServiceAccounts().Informer(),
		namespacedKubeInformers.Core().V1().Secrets().Informer(),
		namespacedKubeInformers.Apps().V1().Deployments().Informer(),
		operatorClient.Informers.Operator().V1().ServiceCAs().Informer(),
	).WithNamespaceInformer(
		namespacedKubeInformers.Core().V1().Namespaces().Informer(), operatorclient.TargetNamespace,
	).WithSync(c.Sync).
		ToController("ServiceCAOperator", eventRecorder.WithComponentSuffix("service-ca-operator"))
}

func (c *serviceCAOperator) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	operatorConfig, err := c.operatorConfigLister.Get("cluster")
	if err != nil {
		return err
	}

	operatorConfigCopy := operatorConfig.DeepCopy()
	switch operatorConfigCopy.Spec.ManagementState {
	case operatorv1.Unmanaged, operatorv1.Removed, "Paused":
		// Totally disable the sync loop in these states until we bump deps and replace sscs.
		return nil
	case operatorv1.Managed:
		// This is to push out deployments but does not handle deployment generation like it used to. It may need tweaking.
		err := syncControllers(c, operatorConfigCopy)
		if err != nil {
			setDegradedTrue(operatorConfigCopy, "OperatorSyncLoopError", err.Error())
		} else {
			setDegradedFalse(operatorConfigCopy, "OperatorSyncLoopComplete")
			existingDeployments, err := c.appsv1Client.Deployments(operatorclient.TargetNamespace).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("Error listing deployments in %s: %v", operatorclient.TargetNamespace, err)
			}
			c.syncStatus(operatorConfigCopy, existingDeployments, targetDeploymentNames)
		}
		c.updateStatus(operatorConfigCopy)
		return err
	}
	return nil
}

func getGeneration(client appsclientv1.AppsV1Interface, ns, name string) int64 {
	deployment, err := client.Deployments(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return -1
	}
	return deployment.Generation
}

func (c serviceCAOperator) updateStatus(operatorConfig *operatorv1.ServiceCA) {
	v1helpers.UpdateStatus(c.operatorClient, func(status *operatorv1.OperatorStatus) error {
		operatorConfig.Status.OperatorStatus.DeepCopyInto(status)
		return nil
	})
}
