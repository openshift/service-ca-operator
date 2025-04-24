package controller

import (
	"context"

	"github.com/spf13/cobra"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/controller/controllercmd"

	"github.com/openshift/service-ca-operator/pkg/controller"
	"github.com/openshift/service-ca-operator/pkg/version"
)

func NewController() *cobra.Command {
	var featureGates map[string]bool

	cmd := controllercmd.
		NewControllerCommandConfig("service-ca-controller", version.Get(), func(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
			return controller.StartServiceCAControllers(ctx, controllerContext, featureGates["ShortCertRotation"])
		}, clock.RealClock{}).
		NewCommand()
	cmd.Use = "controller"
	cmd.Short = "Start the Service CA controllers"
	cmd.Flags().Var(utilflag.NewMapStringBool(&featureGates), "feature-gates", "Comma-separated list of key=value pairs that describe feature gates for alpha/experimental features.")

	return cmd
}
