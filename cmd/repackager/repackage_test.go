package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testSHA        = strings.Repeat("0123456789", 4)
	testCommit     = strings.Repeat("c", 40)
	upstreamDigest = "sha256:" + strings.Repeat("a", 64)
	suseRef        = "ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:" + strings.Repeat("b", 64)
	spdxCheck      = "cosign verify-attestation " + suseRef + " --type spdxjson "
)

const (
	testTag   = "pod-privileged-policy/v1.2.3"
	ownRepo   = "gh api --hostname github.com repos/rancher/suse-security-policies/"
	ownList   = "gh api --hostname github.com --paginate --slurp repos/rancher/suse-security-policies/releases"
	destPull  = "kwctl pull registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3 "
	ownVerify = "cosign verify ghcr.io/rancher/"
)

// attested gives the output of cosign verify-attestation for an SPDX
// attestation of the SBOM that the run wrote. If edit is not nil, it
// changes the SBOM before the attestation is made. An error gives an empty
// output, which the run reports as a different SBOM.
func attested(edit func(sbom map[string]any)) func(work string) string {
	return func(work string) string {
		var sbom map[string]any
		data, err := os.ReadFile(filepath.Join(work, suseSBOMName))
		if err != nil || json.Unmarshal(data, &sbom) != nil {
			return ""
		}
		if edit != nil {
			edit(sbom)
		}
		statement, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document", "predicate": sbom})
		envelope, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(statement), "signatures": []any{}})
		return string(envelope) + "\n"
	}
}

// rerunRules describe a run after an earlier run that pushed and signed the
// module but did not publish the release.
func rerunRules() []rule {
	releaseURL := "https://github.com/kubewarden/policies/releases/tag/" + testTag
	upstreamMD := `rules: [{apiGroups: [""], operations: [CREATE]}]
mutating: false
annotations:
  io.kubewarden.kwctl: 1.20.0
  io.kubewarden.policy.author: Kubewarden developers
  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged
  io.kubewarden.policy.source: https://github.com/kubewarden/policies
  io.kubewarden.policy.version: 1.2.3
`
	repackagedMD := fmt.Sprintf(`rules: [{apiGroups: [""], operations: [CREATE]}]
mutating: false
annotations:
  io.kubewarden.kwctl: 1.21.0
  io.kubewarden.policy.author: "SUSE <containers@suse.com>"
  io.kubewarden.policy.ociUrl: ghcr.io/rancher/suse-security-policies/pod-privileged
  io.kubewarden.policy.source: https://github.com/kubewarden/policies
  io.kubewarden.policy.url: https://github.com/rancher/suse-security-policies
  io.kubewarden.policy.version: 1.2.3
  com.suse.policy.upstream.author: Kubewarden developers
  com.suse.policy.upstream.digest: %s
  com.suse.policy.upstream.release-url: %s
  com.suse.policy.upstream.repository: kubewarden/policies
  com.suse.policy.upstream.tag: %s
`, upstreamDigest, releaseURL, testTag)
	return []rule{
		{prefix: ownRepo + "releases/tags/", err: "gh: Not Found (HTTP 404)"},
		{prefix: ownRepo + "git/ref/tags/", err: "gh: Not Found (HTTP 404)"},
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/releases/tags/", out: fmt.Sprintf(
			`{"tag_name":%q,"html_url":%q,"body":"Fix #12, thanks @alice","published_at":"2026-01-02T03:04:05Z"}`, testTag, releaseURL)},
		{prefix: "gh api --hostname github.com -H Accept: application/vnd.github.raw", out: "annotations:\n" +
			"  io.kubewarden.policy.ociUrl: ghcr.io/kubewarden/policies/pod-privileged\n  io.kubewarden.policy.version: 1.2.3\n"},
		{prefix: "cosign verify ghcr.io/kubewarden/", out: `[{"critical":{"image":{"docker-manifest-digest":"` + upstreamDigest + `"}}}]`},
		{prefix: "kwctl pull registry://ghcr.io/kubewarden/", write: "upstream wasm"},
		{prefix: "kwctl inspect -o yaml $WORK/" + upstreamWasmName, out: upstreamMD},
		{prefix: "kwctl annotate ", write: "suse wasm"},
		{prefix: "kwctl inspect -o yaml $WORK/" + suseWasmName, out: repackagedMD},
		{prefix: "kwctl pull registry://ghcr.io/rancher/", write: "suse wasm"},
		{prefix: "kwctl digest ", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3@sha256:" + strings.Repeat("b", 64) + "\n"},
		{prefix: "gh release download " + testTag + " --repo github.com/kubewarden/policies --pattern " + upstreamSBOMAsset + " ", write: `{
  "documentNamespace": "https://kubewarden.io/spdx/pod-privileged-1.2.3",
  "documentDescribes": ["SPDXRef-Package-src"],
  "packages": [{"SPDXID": "SPDXRef-Package-src", "versionInfo": "` + testCommit + `", "licenseDeclared": "Apache-2.0"}]
}`},
		{prefix: "gh release download " + testTag + " --repo github.com/kubewarden/policies --pattern " + upstreamSBOMBundleAsset + " ", write: "bundle"},
		{prefix: "sbom-utility validate ", out: "valid"},
		// An annotated tag points at a tag object, which points at the commit.
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/ref/tags/", out: `{"object":{"type":"tag","sha":"` + strings.Repeat("d", 40) + `"}}`},
		{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", out: `{"object":{"type":"commit","sha":"` + testCommit + `"}}`},
		{prefix: "gh api --hostname github.com --allow-escape-sequences repos/kubewarden/policies/tarball/", out: "source archive"},
		{prefix: spdxCheck, fn: attested(nil)},
		{prefix: "cosign verify", out: "[]"},
		{prefix: "cosign sign", out: ""},
		{prefix: "cosign attest", out: ""},
		{prefix: ownList, out: "[[]]", once: true},
		{prefix: "gh release create ", out: ""},
		{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":42}]]`},
		{prefix: "gh api --hostname github.com -X PATCH ", out: `{"assets":[{"browser_download_url":"https://github.com/rancher/suse-security-policies/releases/download/` + testTag + `/suse-policy.wasm"}]}`},
	}
}

// freshRules describe a run where the destination tag does not exist and
// no signature verifies.
func freshRules() []rule {
	return append([]rule{
		{prefix: destPull, err: "Error: manifest unknown"},
		{prefix: "kwctl push -o json ", out: `{"immutable_ref":"` + suseRef + `"}`},
		{prefix: ownVerify, err: "no signatures found", once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: "no attestations found", once: true},
		{prefix: "cosign verify-attestation ghcr.io/rancher/", err: "no attestations found", once: true},
	}, rerunRules()...)
}

// renamed gives the policy the id name_unknown, which looks like the OCI
// error code NAME_UNKNOWN.
func renamed(rules []rule) []rule {
	for i := range rules {
		for _, p := range []*string{&rules[i].prefix, &rules[i].out, &rules[i].write} {
			*p = strings.ReplaceAll(*p, "policies/pod-privileged", "policies/name_unknown")
		}
	}
	return rules
}

func TestRepackage(t *testing.T) {
	signOrPublish := []string{"kwctl push", "cosign sign --", "cosign attest", "gh release create", "-X PATCH", "-X DELETE"}
	tests := []struct {
		name    string
		dryRun  bool
		rules   []rule
		wantErr string
		forbid  []string // no command line may contain one of these
		want    []string // each of these command lines must run
		calls   int      // if not 0, the exact number of calls
	}{
		{name: "dry run", dryRun: true, rules: freshRules(), forbid: append(signOrPublish, "cosign sign-blob")},
		{name: "rerun", rules: rerunRules(), forbid: []string{"kwctl push", "cosign sign --", "cosign attest"},
			want: []string{"gh release create", "-X PATCH", "kwctl digest registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3",
				"kwctl pull registry://" + suseRef + " -o $WORK/existing-policy.wasm",
				"cosign verify " + suseRef + " --new-bundle-format=false --output json --certificate-identity https://github.com/rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com"}},
		{name: "destination pull denied", rules: append([]rule{{prefix: destPull, err: "Error: denied: permission denied"}}, rerunRules()...),
			wantErr: "cannot tell whether", forbid: signOrPublish},
		{name: "digest output without a digest", rules: append([]rule{
			{prefix: "kwctl digest ", out: "registry://ghcr.io/rancher/suse-security-policies/pod-privileged:v1.2.3\n"},
		}, rerunRules()...), wantErr: "has no sha256 digest", forbid: signOrPublish},
		// The error names the policy id, which must not count as NAME_UNKNOWN.
		{name: "policy id looks like an error code", rules: append([]rule{{
			prefix: "kwctl pull registry://ghcr.io/rancher/suse-security-policies/name_unknown:v1.2.3 ",
			err:    "Error: Registry error: url https://ghcr.io/v2/rancher/suse-security-policies/name_unknown/manifests/v1.2.3, envelope: OCI API errors: [OCI API error: denied]",
		}}, renamed(rerunRules())...), wantErr: "cannot tell whether", forbid: signOrPublish},
		{name: "already published", rules: append([]rule{{prefix: ownRepo + "releases/tags/", out: "{}"}}, rerunRules()...),
			wantErr: "is already published", calls: 1},
		{name: "tag without a release", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", out: "{}"}}, rerunRules()...),
			wantErr: "exists without a published release", calls: 2},
		{name: "tag lookup fails", rules: append([]rule{{prefix: ownRepo + "git/ref/tags/", err: "gh: Bad credentials (HTTP 401)"}}, rerunRules()...),
			wantErr: "HTTP 401", calls: 2},
		{name: "upstream tag lookup fails", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", err: "gh: Server Error (HTTP 502)"}}, freshRules()...),
			wantErr: "HTTP 502", forbid: []string{"cosign sign", "cosign attest", "gh release create", "/tarball/"}},
		{name: "upstream tag names another commit", rules: append([]rule{{prefix: "gh api --hostname github.com repos/kubewarden/policies/git/tags/", out: `{"object":{"type":"commit","sha":"` + strings.Repeat("e", 40) + `"}}`}}, freshRules()...),
			wantErr: "the upstream SBOM records the commit", forbid: []string{"cosign sign", "cosign attest", "gh release create", "/tarball/"}},
		{name: "destination holds another module", rules: append([]rule{{prefix: "kwctl pull registry://ghcr.io/rancher/", write: "other wasm"}}, freshRules()[1:]...),
			wantErr: "holds another module", forbid: signOrPublish},
		{name: "stale draft", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":7},{"tag_name":"other/v1.0.0","draft":true,"id":9}]]`, once: true},
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":true,"id":42}]]`, once: true},
			{prefix: "gh api --hostname github.com -X DELETE ", out: ""},
		}, rerunRules()...), want: []string{"gh api --hostname github.com -X DELETE repos/rancher/suse-security-policies/releases/7"},
			forbid: []string{"releases/9"}},
		// An earlier run attested an SBOM with another tool name.
		{name: "stale SBOM attestation", rules: append([]rule{{prefix: spdxCheck, fn: attested(func(sbom map[string]any) {
			sbom["creationInfo"].(map[string]any)["creators"] = []any{"Organization: SUSE", "Tool: suse-security-policies-" + testSHA}
		})}}, rerunRules()...), wantErr: "differs from the release SBOM",
			forbid: []string{"cosign sign", "cosign attest", "gh release create", "-X PATCH", "-X DELETE"}},
		{name: "published release in the list", rules: append([]rule{
			{prefix: ownList, out: `[[{"tag_name":"` + testTag + `","draft":false,"id":8}]]`, once: true},
		}, rerunRules()...), wantErr: "is already published", forbid: []string{"-X DELETE", "gh release create"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			work := t.TempDir()
			f := newFake(t, work, tt.rules...)
			args := []string{"repackage", "--config", "testdata/config.yaml", "--repository", "rancher/suse-security-policies", "--sha", testSHA,
				"--policy-name", "pod-privileged-policy", "--policy-version", "1.2.3", "--work-dir", work}
			if tt.dryRun {
				args = append(args, "--dry-run")
			}
			_, err := execute(t, args...)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("repackage failed: %v", err)
			} else if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("repackage returned the error %v, but the test expects an error with %q", err, tt.wantErr)
			}
			if tt.calls != 0 && len(f.calls) != tt.calls {
				t.Errorf("repackage ran %d commands instead of %d:\n%s", len(f.calls), tt.calls, strings.Join(f.calls, "\n"))
			}
			for _, call := range f.calls {
				for _, s := range tt.forbid {
					if strings.Contains(call, s) {
						t.Errorf("the command %q must not run", call)
					}
				}
			}
			for _, w := range tt.want {
				if !strings.Contains(strings.Join(f.calls, "\n"), w) {
					t.Errorf("no command contains %q", w)
				}
			}
		})
	}
}
