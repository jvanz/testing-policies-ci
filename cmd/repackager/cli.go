package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var gh string

func newRootCommand() *cobra.Command {
	var configPath, repo, policyName, policyVersion string
	var dryRun bool
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

	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Find the upstream releases that still need a repackaging",
		Long: `Find the upstream releases that still need a repackaging. Print them as a
compact JSON list on stdout. In GitHub Actions, also set the step outputs
"matrix" and "count" and write the job summary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := setup(cmd, configPath, "repository", "gh")
			if err != nil {
				return err
			}
			releases, err := discover(cmd.Context(), cfg, repo, policyName, policyVersion)
			if err != nil {
				return err
			}
			matrix, _ := json.Marshal(releases)
			fmt.Fprintf(cmdOut, "%s\n", matrix)
			if err := appendEnvFile("GITHUB_OUTPUT", io.Discard, fmt.Sprintf("matrix=%s\ncount=%d\n", matrix, len(releases))); err != nil {
				return err
			}
			// Outside GitHub Actions, stdout holds only the JSON list.
			return appendEnvFile("GITHUB_STEP_SUMMARY", logOut, discoverySummary(releases, dryRun))
		},
	}
	df := discoverCmd.Flags()
	df.StringVar(&repo, "repository", "", "owner/repo of this repository (required)")
	df.StringVar(&policyName, "policy-name", "", "find only the release of this policy")
	df.StringVar(&policyVersion, "policy-version", "", "find only this version, without the 'v' prefix. Needs --policy-name")
	df.BoolVar(&dryRun, "dry-run", false, "mark the job summary as a dry run")
	df.StringVar(&gh, "gh", "gh", "path of the gh program, or its name on the PATH")

	root.AddCommand(checkConfig, discoverCmd)
	return root
}

// setup rejects an empty required flag, because make passes an unset
// variable as an empty string.
func setup(cmd *cobra.Command, configPath string, required ...string) (*config, error) {
	var missing []string
	for _, name := range required {
		if strings.TrimSpace(cmd.Flags().Lookup(name).Value.String()) == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("these flags are required and must not be empty: %s", strings.Join(missing, ", "))
	}
	return loadConfig(configPath)
}
