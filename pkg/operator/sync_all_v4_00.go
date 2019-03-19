package operator

import (
	operatorv1 "github.com/openshift/api/operator/v1"
)

// sync_v4_00_to_latest takes care of synchronizing (not upgrading) the thing we're managing.
// most of the time the sync method will be good for a large span of minor versions
func sync_v4_00_to_latest(c serviceCAOperator, operatorConfig *operatorv1.ServiceCA) error {
	err := syncSigningController_v4_00_to_latest(c, operatorConfig)
	if err != nil {
		return err
	}
	err = syncAPIServiceController_v4_00_to_latest(c, operatorConfig)
	if err != nil {
		return err
	}
	err = syncConfigMapCABundleController_v4_00_to_latest(c, operatorConfig)
	if err != nil {
		return err
	}
	return nil
}
