package cmd

import (
	"github.com/spf13/cobra"
)

// RootCmd is cobra command.
var RootCmd = &cobra.Command{
	Use:           "xliic-firewall-injector",
	Short:         "xliic-firewall-injector is a webhook server to inject 42Crunch firewall as sidecar",
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	cobra.OnInitialize()
	RootCmd.AddCommand(
		serverCmd(),
		versionCmd(),
	)
}
