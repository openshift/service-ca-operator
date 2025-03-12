package operator

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacclientv1 "k8s.io/client-go/kubernetes/typed/rbac/v1"

	operatorv1 "github.com/openshift/api/operator/v1"
	_ "github.com/openshift/api/operator/v1/zz_generated.crd-manifests"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
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
	infrastructureLister configv1listers.InfrastructureLister

	appsv1Client  appsclientv1.AppsV1Interface
	corev1Client  coreclientv1.CoreV1Interface
	rbacv1Client  rbacclientv1.RbacV1Interface
	versionGetter status.VersionGetter
	eventRecorder events.Recorder

	minimumTrustDuration       time.Duration
	signingCertificateLifetime time.Duration
}

func NewServiceCAOperator(
	operatorClient *operatorclient.OperatorClient,

	namespacedKubeInformers informers.SharedInformerFactory,
	configInformers configv1informers.SharedInformerFactory,
	appsv1Client appsclientv1.AppsV1Interface,
	corev1Client coreclientv1.CoreV1Interface,
	rbacv1Client rbacclientv1.RbacV1Interface,
	versionGetter status.VersionGetter,
	eventRecorder events.Recorder,
	minimumTrustDuration time.Duration,
	signingCertificateLifetime time.Duration,
) factory.Controller {
	c := &serviceCAOperator{
		operatorClient:       operatorClient,
		operatorConfigLister: operatorClient.Informers.Operator().V1().ServiceCAs().Lister(),
		infrastructureLister: configInformers.Config().V1().Infrastructures().Lister(),

		appsv1Client:  appsv1Client,
		corev1Client:  corev1Client,
		rbacv1Client:  rbacv1Client,
		versionGetter: versionGetter,
		eventRecorder: eventRecorder,

		minimumTrustDuration:       minimumTrustDuration,
		signingCertificateLifetime: signingCertificateLifetime,
	}

	return factory.New().WithInformers(
		namespacedKubeInformers.Core().V1().ConfigMaps().Informer(),
		namespacedKubeInformers.Core().V1().ServiceAccounts().Informer(),
		namespacedKubeInformers.Core().V1().Secrets().Informer(),
		namespacedKubeInformers.Apps().V1().Deployments().Informer(),
		operatorClient.Informers.Operator().V1().ServiceCAs().Informer(),
		configInformers.Config().V1().Infrastructures().Informer(),
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
	infrastructure, err := c.infrastructureLister.Get("cluster")
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
		err := c.syncControllers(ctx, operatorConfigCopy, infrastructure)
		if err != nil {
			setDegradedTrue(operatorConfigCopy, "OperatorSyncLoopError", err.Error())
		} else {
			setDegradedFalse(operatorConfigCopy, "OperatorSyncLoopComplete")
			existingDeployments, err := c.appsv1Client.Deployments(operatorclient.TargetNamespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("error listing deployments in %s: %v", operatorclient.TargetNamespace, err)
			}
			c.syncStatus(operatorConfigCopy, existingDeployments, targetDeploymentNames)
		}
		setUpgradeableTrue(operatorConfigCopy, "AsExpected")
		c.updateStatus(ctx, operatorConfigCopy)
		return err
	}
	return nil
}

func (c serviceCAOperator) updateStatus(ctx context.Context, operatorConfig *operatorv1.ServiceCA) {
	v1helpers.UpdateStatus(ctx, c.operatorClient, func(status *operatorv1.OperatorStatus) error {
		operatorConfig.Status.OperatorStatus.DeepCopyInto(status)
		return nil
	})
}
