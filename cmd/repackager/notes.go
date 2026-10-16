package main

import "fmt"

func discoverySummary(releases []map[string]string, dryRun bool) string {
	s := "### Policies queued for repackaging\n\n"
	if dryRun {
		s += "Dry run: the workflow publishes nothing.\n\n"
	}
	if len(releases) == 0 {
		return s + "Nothing to do. Every upstream release already has a matching release here.\n"
	}
	s += "| Policy | Version | Upstream release |\n|---|---|---|\n"
	for _, r := range releases {
		s += fmt.Sprintf("| %s | %s | [%s](%s) |\n", r["policy_name"], r["version"], r["tag"], r["upstream_release_url"])
	}
	return s
}
