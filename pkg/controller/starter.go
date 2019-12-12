package controller

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	apistart "github.com/openshift/service-ca-operator/pkg/controller/apiservicecabundle/starter"
	cmstart "github.com/openshift/service-ca-operator/pkg/controller/configmapcainjector/starter"
	certstart "github.com/openshift/service-ca-operator/pkg/controller/servingcert/starter"
)

func StartServiceCAControllers(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	err := apistart.StartAPIServiceCABundleInjector(ctx, controllerContext)
	if err != nil {
		return err
	}
	err = cmstart.StartConfigMapCABundleInjector(ctx, controllerContext)
	if err != nil {
		return err
	}
	err = certstart.StartServiceServingCertSigner(ctx, controllerContext)
	if err != nil {
		return err
	}

	<-ctx.Done()

	return fmt.Errorf("stopped")
}
