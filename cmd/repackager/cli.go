package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var configPath string
	root := &cobra.Command{Use: "repackager", Short: "Repackage upstream Kubewarden policies as SUSE policies", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "path of the config file")

	checkConfig := &cobra.Command{Use: "check-config", Short: "Check that the config file has every value the pipeline needs", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := loadConfig(configPath)
			if err == nil {
				_, err = fmt.Fprintf(cmdOut, "%s is valid\n", configPath)
			}
			return err
		}}

	root.AddCommand(checkConfig)
	return root
}
