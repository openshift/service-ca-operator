package operator

import (
	"context"
	"sync"

	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"
)

type TryOnce struct {
	lock      sync.Mutex
	succeeded bool
}

func (o *TryOnce) Do(f func() error) error {
	o.lock.Lock()
	defer o.lock.Unlock()

	if o.succeeded {
		return nil
	}

	err := f()
	o.succeeded = err == nil
	return err
}

var once = TryOnce{}

func (c *serviceCAOperator) syncControllers(ctx context.Context, operatorConfig *operatorv1.ServiceCA) error {
	// Any modification of resource we want to trickle down to force deploy all of the controllers.
	// Sync the controller NS and the other resources. These should be mostly static.
	needsDeploy, err := c.manageControllerNS()
	if err != nil {
		return err
	}

	err = c.manageControllerResources(&needsDeploy)
	if err != nil {
		return err
	}

	// Sync the CA (regenerate if missing).
	caModified, err := c.manageSignerCA(ctx, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return err
	}
	// Sync the CA bundle. This will be updated if the CA has changed.
	_, err = c.manageSignerCABundle(ctx, caModified)
	if err != nil {
		return err
	}

	// Sync the controller.
	_, err = c.manageDeployment(operatorConfig, needsDeploy || caModified)
	if err != nil {
		return err
	}

	klog.V(4).Infof("synced all controller resources")
	return nil
}
