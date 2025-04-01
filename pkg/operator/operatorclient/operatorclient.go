package operatorclient

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorv1apply "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1"
	operatorv1informers "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

type OperatorClient struct {
	Clock     clock.PassiveClock
	Informers operatorv1informers.SharedInformerFactory
	Client    operatorv1client.OperatorV1Interface
}

func (c OperatorClient) GetObjectMeta() (*metav1.ObjectMeta, error) {
	// This method is required by the library-go interface but is
	// unused in this repo so there's no point in implementing at this
	// time.
	return nil, fmt.Errorf("not implemented")
}

func (c *OperatorClient) Informer() cache.SharedIndexInformer {
	return c.Informers.Operator().V1().ServiceCAs().Informer()
}

func (c *OperatorClient) GetOperatorState() (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	instance, err := c.Informers.Operator().V1().ServiceCAs().Lister().Get(api.OperatorConfigInstanceName)
	if err != nil {
		return nil, nil, "", err
	}

	return &instance.Spec.OperatorSpec, &instance.Status.OperatorStatus, instance.ResourceVersion, nil
}

func (c *OperatorClient) UpdateOperatorSpec(ctx context.Context, resourceVersion string, spec *operatorv1.OperatorSpec) (*operatorv1.OperatorSpec, string, error) {
	original, err := c.Informers.Operator().V1().ServiceCAs().Lister().Get(api.OperatorConfigInstanceName)
	if err != nil {
		return nil, "", err
	}
	copy := original.DeepCopy()
	copy.ResourceVersion = resourceVersion
	copy.Spec.OperatorSpec = *spec

	ret, err := c.Client.ServiceCAs().Update(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, "", err
	}

	return &ret.Spec.OperatorSpec, ret.ResourceVersion, nil
}

func (c *OperatorClient) UpdateOperatorStatus(ctx context.Context, resourceVersion string, status *operatorv1.OperatorStatus) (*operatorv1.OperatorStatus, error) {
	original, err := c.Informers.Operator().V1().ServiceCAs().Lister().Get(api.OperatorConfigInstanceName)
	if err != nil {
		return nil, err
	}
	copy := original.DeepCopy()
	copy.ResourceVersion = resourceVersion
	copy.Status.OperatorStatus = *status

	ret, err := c.Client.ServiceCAs().UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	return &ret.Status.OperatorStatus, nil
}

func (c *OperatorClient) ApplyOperatorSpec(ctx context.Context, fieldManager string, desiredConfiguration *operatorv1apply.OperatorSpecApplyConfiguration) error {
	if desiredConfiguration == nil {
		return fmt.Errorf("desiredConfiguration must have a value")
	}
	desiredSpec := &operatorv1apply.ServiceCASpecApplyConfiguration{
		OperatorSpecApplyConfiguration: *desiredConfiguration,
	}
	desired := operatorv1apply.ServiceCA(api.OperatorConfigInstanceName)
	desired.WithSpec(desiredSpec)

	instance, err := c.Informers.Operator().V1().ServiceCAs().Lister().Get(api.OperatorConfigInstanceName)
	switch {
	case apierrors.IsNotFound(err):
	// do nothing and proceed with the apply
	case err != nil:
		return fmt.Errorf("unable to get operator configuration: %w", err)
	default:
		original, err := operatorv1apply.ExtractServiceCA(instance, fieldManager)
		if err != nil {
			return fmt.Errorf("unable to extract operator configuration: %w", err)
		}
		if equality.Semantic.DeepEqual(original, desired) {
			return nil
		}
	}

	_, err = c.Client.ServiceCAs().Apply(ctx, desired, metav1.ApplyOptions{
		Force:        true,
		FieldManager: fieldManager,
	})
	if err != nil {
		return fmt.Errorf("unable to Apply service CA using fieldManager %q: %w", fieldManager, err)
	}

	return nil
}

func (c *OperatorClient) GetOperatorStateWithQuorum(ctx context.Context) (*operatorv1.OperatorSpec, *operatorv1.OperatorStatus, string, error) {
	instance, err := c.Client.ServiceCAs().Get(ctx, api.OperatorConfigInstanceName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, "", err
	}

	return &instance.Spec.OperatorSpec, &instance.Status.OperatorStatus, instance.GetResourceVersion(), nil
}
