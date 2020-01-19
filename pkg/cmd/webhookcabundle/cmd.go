package webhookcabundle

import (
	"github.com/spf13/cobra"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/openshift/service-ca-operator/pkg/controller/webhookcabundle/starter"
	"github.com/openshift/service-ca-operator/pkg/version"
)

const (
	componentName      = "webhook-cabundle-injector"
	componentNamespace = "openshift-service-ca"
)

func NewController() *cobra.Command {
	cmd := controllercmd.
		NewControllerCommandConfig(componentName, version.Get(), starter.StartWebhookCABundleInjector).
		NewCommand()
	cmd.Use = "webhook-cabundle-injector"
	cmd.Short = "Start the WebHook CA Bundle Injection controller"
	return cmd
}
