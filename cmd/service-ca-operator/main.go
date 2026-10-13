package main

import (
	"os"

	"github.com/spf13/cobra"

	"k8s.io/component-base/cli"

	"github.com/openshift/service-ca-operator/pkg/cmd/controller"
	"github.com/openshift/service-ca-operator/pkg/cmd/operator"
)

func main() {
	os.Exit(cli.Run(NewSSCSCommand()))
}

func NewSSCSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service-ca-operator",
		Short: "OpenShift Service CA Operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}

	cmd.AddCommand(operator.NewOperator())
	cmd.AddCommand(controller.NewController())

	return cmd
}
