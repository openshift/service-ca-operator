package controller

import (
	"context"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/cabundleinjector"
	certstart "github.com/openshift/service-ca-operator/pkg/controller/servingcert/starter"
)

func StartServiceCAControllers(ctx context.Context, controllerContext *controllercmd.ControllerContext, shortCertRotationEnabled bool) error {
	err := cabundleinjector.StartCABundleInjector(ctx, controllerContext)
	if err != nil {
		return err
	}
	err = certstart.StartServiceServingCertSigner(ctx, controllerContext, shortCertRotationEnabled)
	if err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
