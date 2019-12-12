package operator

import (
	"sync"

	"k8s.io/klog"

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

func syncControllers(c serviceCAOperator, operatorConfig *operatorv1.ServiceCA) error {
	// Any modification of resource we want to trickle down to force deploy all of the controllers.
	// Sync the controller NS and the other resources. These should be mostly static.
	needsDeploy, err := manageControllerNS(c)
	if err != nil {
		return err
	}

	if err := once.Do(func() error { return cleanupDeprecatedResources(c) }); err != nil {
		return err
	}

	err = manageSignerControllerResources(c, &needsDeploy)
	if err != nil {
		return err
	}

	err = manageAPIServiceControllerResources(c, &needsDeploy)
	if err != nil {
		return err
	}

	err = manageConfigMapCABundleControllerResources(c, &needsDeploy)
	if err != nil {
		return err
	}

	// Sync the CA (regenerate if missing).
	caModified, err := manageSignerCA(c.corev1Client, c.eventRecorder, operatorConfig.Spec.UnsupportedConfigOverrides.Raw)
	if err != nil {
		return err
	}
	// Sync the CA bundle. This will be updated if the CA has changed.
	_, err = manageSignerCABundle(c.corev1Client, c.eventRecorder, caModified)
	if err != nil {
		return err
	}

	// Sync the signing controller.
	_, err = manageSignerControllerDeployment(c.appsv1Client, c.eventRecorder, operatorConfig, needsDeploy || caModified)
	if err != nil {
		return err
	}

	// Sync the API service controller.
	_, err = manageAPIServiceControllerDeployment(c.appsv1Client, c.eventRecorder, operatorConfig, needsDeploy || caModified)
	if err != nil {
		return err
	}

	// Sync the API service controller.
	_, err = manageConfigMapCABundleControllerDeployment(c.appsv1Client, c.eventRecorder, operatorConfig, needsDeploy || caModified)
	if err != nil {
		return err
	}

	klog.V(4).Infof("synced all controller resources")
	return nil
}
