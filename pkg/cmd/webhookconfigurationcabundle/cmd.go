package webhookconfigurationcabundle

import (
	"github.com/spf13/cobra"

	"github.com/openshift/library-go/pkg/controller/controllercmd"

	"github.com/openshift/service-ca-operator/pkg/controller/webhookconfigurationcabundle/starter"
	"github.com/openshift/service-ca-operator/pkg/version"
)

const componentName = "openshift-service-ca-operator-webhookconfiguration-cabundle-injector"

func NewController() *cobra.Command {
	cmd := controllercmd.
		NewControllerCommandConfig(componentName, version.Get(), starter.StartWebhookConfigurationCABundleInjector).
		NewCommand()
	cmd.Use = "webhookconfiguration-cabundle-injector"
	cmd.Short = "Start the WebhookConfiguration CA Bundle Injection controller"
	return cmd
}
