package controller

import (
	"github.com/spf13/cobra"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/controller/controllercmd"

	"github.com/openshift/service-ca-operator/pkg/controller"
	"github.com/openshift/service-ca-operator/pkg/version"
)

func NewController() *cobra.Command {
	cmd := controllercmd.
		NewControllerCommandConfig("service-ca-controller", version.Get(), controller.StartServiceCAControllers, clock.RealClock{}).
		NewCommand()
	cmd.Use = "controller"
	cmd.Short = "Start the Service CA controllers"
	return cmd
}
