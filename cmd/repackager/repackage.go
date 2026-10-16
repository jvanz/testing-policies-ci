package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	suseWasmName     = "suse-policy.wasm"
	upstreamSBOMName = "upstream-policy-sbom.spdx.json"
	suseSBOMName     = "policy-sbom.spdx.json"
	keyOCIURL        = "io.kubewarden.policy.ociUrl"
	keyAuthor        = "io.kubewarden.policy.author"
	keyVersion       = "io.kubewarden.policy.version"
)

var (
	// A short SHA or a branch name does not always name one fixed commit.
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// kwctl reports a tag that is not in the registry with these OCI codes.
	notFoundPattern = regexp.MustCompile(`(?i)(manifest|name)[ _]unknown`)
)

type job struct {
	cfg                                                                   *config
	repo, sha, workDir                                                    string
	dryRun                                                                bool
	name, version, tag, id, url                                           string
	upstream, upstreamRoot                                                any
	upstreamDigest, upstreamRef, immutableRef                             string
	destRef, sourceCommit, sourceSHA256, upstreamNamespace, suseNamespace string
}

func (j *job) path(name string) string { return filepath.Join(j.workDir, name) }

// Sigstore compares the identity exactly, so the tag needs no escaping.
func (j *job) identity(own bool) []string {
	if own {
		return []string{"--certificate-identity", "https://github.com/" + j.repo + "/.github/workflows/sync-upstream-releases.yaml@refs/heads/main",
			"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"}
	}
	return []string{"--certificate-identity", strings.ReplaceAll(j.cfg.Upstream.CertificateIdentityTemplate, "{tag}", j.tag),
		"--certificate-oidc-issuer", j.cfg.Upstream.CertificateOIDCIssuer}
}

// The --type filter makes sure that the SBOM attestation, which is also a
// v3 bundle, does not count as a signature.
func verifyArgs(ref string, identity []string) (legacy, bundle []string) {
	return append([]string{"verify", ref, "--new-bundle-format=false", "--output", "json"}, identity...),
		append([]string{"verify-attestation", ref, "--type", "https://sigstore.dev/cosign/sign/v1"}, identity...)
}

func repackage(ctx context.Context, j *job) error {
	if err := checkPolicy(j.cfg, j.name, j.version); err != nil {
		return fmt.Errorf("repackage: %w", err)
	} else if !shaPattern.MatchString(j.sha) {
		return fmt.Errorf("repackage: --sha %q is not a full commit SHA of 40 lowercase hex characters", j.sha)
	}
	j.tag = j.name + "/v" + j.version
	var err error
	if j.workDir == "" {
		j.workDir, err = os.MkdirTemp("", "repackager-*")
		defer os.RemoveAll(j.workDir)
	} else {
		err = os.MkdirAll(j.workDir, 0o755)
	}
	do := func(title string, fn func(context.Context, *job) error) {
		if err == nil {
			err = step(title, func() error { return fn(ctx, j) })
		}
	}
	do("Find the upstream release", findUpstream)
	do("Verify the upstream policy signature", verifyUpstream)
	do("Annotate the policy", annotate)
	do("Push the repackaged policy", push)
	do("Download and verify the upstream SBOM", upstreamSBOM)
	do("Generate the SUSE SBOM", suseSBOM)
	do("Download the upstream source archive and render the release notes", downloadSource)
	if !j.dryRun {
		do("Sign and attest", sign)
		do("Publish the release", publish)
	} else if err == nil {
		logf("::notice::Dry run: the program does not push, sign or publish anything")
	}
	if err != nil {
		return fmt.Errorf("repackage %s: %w", j.tag, err)
	}
	return nil
}

// findUpstream stops the run before anything is pushed or signed when our
// release or tag exists. It checks the upstream release like discover.
func findUpstream(ctx context.Context, j *job) error {
	for _, c := range [][2]string{
		{"releases/tags/", "the release %s is already published"},
		{"git/ref/tags/", "the tag %s exists without a published release. A person must check the tag"},
	} {
		if _, err := run(ctx, gh, ghArgs("repos/"+j.repo+"/"+c[0]+j.tag)...); err == nil {
			return fmt.Errorf(c[1], j.tag)
		} else if !strings.Contains(err.Error(), "HTTP 404") {
			return err
		}
	}
	rel, err := runJSON(ctx, gh, ghArgs("repos/"+j.cfg.Upstream.Repository+"/releases/tags/"+j.tag)...)
	e := candidate(rel)
	if err == nil && e == nil {
		err = fmt.Errorf("%s has no release %s, or the release is a prerelease", j.cfg.Upstream.Repository, j.tag)
	}
	if err != nil {
		return err
	}
	j.url, j.upstream = e["upstream_release_url"], rel
	j.id, _, err = policyID(ctx, j.cfg, e)
	return err
}

// Later steps use the digest, so a tag that moves changes nothing.
func verifyUpstream(ctx context.Context, j *job) error {
	repo := j.cfg.Upstream.Registry + "/" + j.id
	legacy, _ := verifyArgs(repo+":v"+j.version, j.identity(false))
	// cosign makes sure that each signed payload names the verified digest.
	out, err := runJSON(ctx, cosign, legacy...)
	if sigs := list(out); err == nil && len(sigs) > 0 {
		j.upstreamDigest = str(sigs[0], "critical", "image", "docker-manifest-digest")
	}
	if err != nil || !digestPattern.MatchString(j.upstreamDigest) {
		return cmp.Or(err, fmt.Errorf("the signature of %s:v%s names no sha256 digest", repo, j.version))
	}
	j.upstreamRef = repo + "@" + j.upstreamDigest
	_, bundle := verifyArgs(j.upstreamRef, j.identity(false))
	_, err = run(ctx, cosign, bundle...)
	return err
}

// annotate keeps "io.kubewarden.policy.source", because this repository
// holds no source code. Without --metadata-path, kwctl keeps the rest.
func annotate(ctx context.Context, j *job) error {
	upstreamWasm, suseWasm := j.path("upstream-policy.wasm"), j.path(suseWasmName)
	upstream, err := runAndInspect(ctx, upstreamWasm, j.path("upstream-metadata.yml"), "pull", "registry://"+j.upstreamRef, "-o", upstreamWasm)
	if v, u := str(upstream, "annotations", keyVersion), str(upstream, "annotations", keyOCIURL); err == nil && (v != j.version || u != j.cfg.Upstream.Registry+"/"+j.id) {
		err = fmt.Errorf("the upstream module has the version %q and points at %q, but the release is %s of %s/%s", v, u, j.version, j.cfg.Upstream.Registry, j.id)
	}
	if err != nil {
		return err
	}
	want := map[string]string{
		keyOCIURL:                              j.cfg.Destination.Registry + "/" + j.id,
		keyAuthor:                              j.cfg.Metadata.Author,
		"io.kubewarden.policy.url":             j.cfg.Metadata.URL,
		"com.suse.policy.upstream.repository":  j.cfg.Upstream.Repository,
		"com.suse.policy.upstream.tag":         j.tag,
		"com.suse.policy.upstream.digest":      j.upstreamDigest,
		"com.suse.policy.upstream.release-url": j.url,
		"com.suse.policy.upstream.author":      str(upstream, "annotations", keyAuthor),
	}
	args := []string{"annotate"}
	for _, k := range slices.Sorted(maps.Keys(want)) {
		// kwctl reads KEY=@PATH as "read the value from the file at PATH".
		if v := want[k]; v == "" || v == "null" || strings.HasPrefix(v, "@") || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("the value %q of %s is empty or \"null\", starts with '@', or has a newline", v, k)
		}
		args = append(args, "--annotation", k+"="+want[k])
	}
	repackaged, err := runAndInspect(ctx, suseWasm, j.path("repackaged-metadata.yml"), append(args, "-o", suseWasm, upstreamWasm)...)
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got := str(repackaged, "annotations", k); err == nil && got != want[k] {
			err = fmt.Errorf("the repackaged policy has %s=%q instead of %q", k, got, want[k])
		}
	}
	// Without the new annotations, both documents must be equal. kwctl
	// annotate always writes its own version into "io.kubewarden.kwctl".
	for _, md := range []any{upstream, repackaged} {
		a, _ := get(md, "annotations").(map[string]any)
		maps.DeleteFunc(a, func(k string, _ any) bool { return want[k] != "" || k == "io.kubewarden.kwctl" })
	}
	if err == nil && !reflect.DeepEqual(upstream, repackaged) {
		err = errors.New("the repackaged policy changed metadata outside of the annotation allowlist. To compare upstream-metadata.yml and repackaged-metadata.yml, run again with --work-dir")
	}
	return err
}

func runAndInspect(ctx context.Context, wasm, out string, args ...string) (md any, err error) {
	data, err := run(ctx, kwctl, args...)
	if err == nil {
		data, err = run(ctx, kwctl, "inspect", "-o", "yaml", wasm)
	}
	if err == nil {
		err = errors.Join(os.WriteFile(out, data, 0o644), yaml.Unmarshal(data, &md))
	}
	return md, err
}

// push never moves a tag, but reuses a tag with the same module bytes,
// because two pushes of one module can give two manifests. The second pull
// is by digest, so the tag cannot move before the signature.
func push(ctx context.Context, j *job) error {
	repo := j.cfg.Destination.Registry + "/" + j.id
	j.destRef = repo + ":v" + j.version
	suseWasm, existing := j.path(suseWasmName), j.path("existing-policy.wasm")
	_, err := run(ctx, kwctl, "pull", "registry://"+j.destRef, "-o", existing)
	switch {
	// The policy id comes from upstream, so it must not make the match.
	case err != nil && !notFoundPattern.MatchString(strings.ReplaceAll(err.Error(), j.id, "")):
		return fmt.Errorf("cannot tell whether %s already exists: %w", j.destRef, err)
	case err != nil && j.dryRun:
		logf("::notice::Dry run: the program does not push %s, so it does not generate or validate the SUSE SBOM", j.destRef)
		return nil
	case err != nil:
		out, err := runJSON(ctx, kwctl, "push", "-o", "json", suseWasm, j.destRef)
		if j.immutableRef = str(out, "immutable_ref"); err == nil && !digestPattern.MatchString(strings.TrimPrefix(j.immutableRef, repo+"@")) {
			err = fmt.Errorf("kwctl push returned %q, which is not a digest reference of %s", j.immutableRef, repo)
		}
		return err
	}
	out, err := run(ctx, kwctl, "digest", "registry://"+j.destRef)
	ref := repo + "@" + strings.TrimSpace(string(out[bytes.LastIndexByte(out, '@')+1:]))
	if err == nil && !digestPattern.MatchString(strings.TrimPrefix(ref, repo+"@")) {
		err = fmt.Errorf("kwctl digest %s printed %q, which has no sha256 digest", j.destRef, strings.TrimSpace(string(out)))
	} else if err == nil {
		_, err = run(ctx, kwctl, "pull", "registry://"+ref, "-o", existing)
	}
	got, _ := fileSHA256(existing)
	if want, _ := fileSHA256(suseWasm); err == nil && got != want {
		err = fmt.Errorf("%s already exists and points at %s, which holds another module (sha256 %s, expected %s). The pipeline does not move a tag. A person must check the artifact and delete it by hand", j.destRef, ref, got, want)
	}
	j.immutableRef = ref
	return err
}

// upstreamSBOM verifies the copy that goes into the release.
func upstreamSBOM(ctx context.Context, j *job) error {
	sbom, bundle := j.path(upstreamSBOMName), j.path("upstream-policy-sbom.spdx.jsonl.bundle.sigstore")
	for _, d := range [][2]string{{"policy-sbom.spdx.json", sbom}, {"policy-sbom.spdx.jsonl.bundle.sigstore", bundle}} {
		if _, err := run(ctx, gh, "release", "download", j.tag, "--repo", "github.com/"+j.cfg.Upstream.Repository,
			"--pattern", d[0], "--output", d[1], "--clobber"); err != nil {
			return err
		}
	}
	_, err := run(ctx, cosign, append([]string{"verify-blob", sbom, "--bundle", bundle}, j.identity(false)...)...)
	if err != nil {
		return err
	}
	doc, err := readJSON(sbom)
	j.upstreamNamespace = str(doc, "documentNamespace")
	if err != nil {
		return fmt.Errorf("parse the upstream SBOM: %w", err)
	} else if j.upstreamRoot, err = upstreamRoot(doc); err == nil && j.upstreamNamespace == "" {
		err = errors.New("the upstream SBOM has no documentNamespace, so the SUSE SBOM cannot refer to it")
	}
	return err
}

// downloadSource downloads by commit. Upstream does not sign the archive,
// so the commit in the upstream SBOM is the only link to check.
func downloadSource(ctx context.Context, j *job) error {
	repo, archive := "repos/"+j.cfg.Upstream.Repository, j.path("upstream-source.tar.gz")
	ref, err := runJSON(ctx, gh, ghArgs(repo+"/git/ref/tags/"+j.tag)...)
	// An annotated tag points at a tag object. The limit stops a loop.
	for depth := 0; err == nil && depth < 10 && str(ref, "object", "type") == "tag"; depth++ {
		ref, err = runJSON(ctx, gh, ghArgs(repo+"/git/tags/"+str(ref, "object", "sha"))...)
	}
	if err != nil {
		return err
	}
	j.sourceCommit = str(ref, "object", "sha")
	if typ, want := str(ref, "object", "type"), str(j.upstreamRoot, "versionInfo"); typ != "commit" || j.sourceCommit != want || !shaPattern.MatchString(want) {
		return fmt.Errorf("%s points at the %s %q, but the upstream SBOM records the commit %q", j.tag, typ, j.sourceCommit, want)
	}
	data, err := run(ctx, gh, ghArgs("--allow-escape-sequences", repo+"/tarball/"+j.sourceCommit)...)
	if err == nil {
		err = os.WriteFile(archive, data, 0o644)
	}
	j.sourceSHA256, _ = fileSHA256(archive)
	notes := []byte(renderReleaseNotes(j, cmp.Or(j.immutableRef, "<not pushed: dry run>"), str(j.upstream, "body")))
	return errors.Join(err, os.WriteFile(j.path("release-notes.md"), notes, 0o644))
}

// sign keeps a signature or an attestation of an earlier run that
// verifies. The legacy signature can carry only a Rekor v1 entry and no
// timestamp, so it does not use the signing config.
func sign(ctx context.Context, j *job) error {
	ref, wasm, sbom := j.immutableRef, j.path(suseWasmName), j.path(suseSBOMName)
	wasmBundle, sbomBundle := wasm+".bundle.sigstore", j.path("policy-sbom.spdx.jsonl.bundle.sigstore")
	own := j.identity(true)
	legacy, bundle := verifyArgs(ref, own)
	spdx := append([]string{"verify-attestation", ref, "--type", "spdxjson"}, own...)
	// An attestation of an earlier run can hold an older SBOM. This check
	// runs before any write, so that a stale attestation changes nothing.
	if out, err := run(ctx, cosign, spdx...); err == nil {
		if err := sameSBOM(ref, out, sbom); err != nil {
			return err
		}
	} else if _, err := run(ctx, cosign, "attest", "--yes", "--type", "spdxjson", "--predicate", sbom, ref); err != nil {
		return err
	}
	for _, s := range [][2][]string{
		{legacy, {"sign", "--yes", "--new-bundle-format=false", "--use-signing-config=false", ref}},
		{bundle, {"sign", "--yes", "--use-signing-config=true", ref}},
	} {
		if _, err := run(ctx, cosign, s[0]...); err != nil {
			if _, err := run(ctx, cosign, s[1]...); err != nil {
				return err
			}
		}
	}
	for _, args := range [][]string{
		{"sign-blob", "--yes", "--bundle", wasmBundle, wasm},
		{"sign-blob", "--yes", "--bundle", sbomBundle, sbom},
		legacy, bundle, spdx,
		append([]string{"verify-blob", wasm, "--bundle", wasmBundle}, own...),
		append([]string{"verify-blob", sbom, "--bundle", sbomBundle}, own...),
	} {
		out, err := run(ctx, cosign, args...)
		if err == nil && slices.Equal(args, spdx) {
			err = sameSBOM(ref, out, sbom)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// sameSBOM returns nil if one attestation in the output of cosign
// verify-attestation holds the release SBOM. cosign prints one DSSE envelope
// per line, and its payload is the in-toto statement.
func sameSBOM(ref string, out []byte, sbom string) error {
	want, err := readJSON(sbom)
	for line := range bytes.Lines(out) {
		envelope, _ := decode(line, nil)
		payload, _ := base64.StdEncoding.DecodeString(str(envelope, "payload"))
		statement, _ := decode(payload, nil)
		got := get(statement, "predicate")
		// Some cosign versions store the document as a JSON string.
		if s, ok := got.(string); ok {
			got, _ = decode([]byte(s), nil)
		}
		if err == nil && reflect.DeepEqual(got, want) {
			return nil
		}
	}
	return cmp.Or(err, fmt.Errorf("the SBOM attestation of %s differs from the release SBOM. A person must delete the old attestation and run again", ref))
}

// publish uploads to a draft first, because only a draft can change.
// GitHub creates the tag at --sha on the publication.
func publish(ctx context.Context, j *job) error {
	assets := []string{j.path(suseWasmName), j.path("suse-policy.wasm.bundle.sigstore"), j.path("upstream-source.tar.gz"), j.path(suseSBOMName),
		j.path("policy-sbom.spdx.jsonl.bundle.sigstore"), j.path(upstreamSBOMName), j.path("upstream-policy-sbom.spdx.jsonl.bundle.sigstore")}
	releases, err := releasesOf(ctx, j.repo)
	for _, r := range releases {
		if str(r, "tag_name") != j.tag || err != nil {
			continue
		} else if get(r, "draft") != true {
			return fmt.Errorf("the release %s is already published", j.tag)
		}
		_, err = run(ctx, gh, ghArgs("-X", "DELETE", fmt.Sprintf("repos/%s/releases/%.0f", j.repo, get(r, "id")))...)
	}
	if err == nil {
		_, err = run(ctx, gh, append([]string{"release", "create", j.tag, "--repo", "github.com/" + j.repo, "--draft",
			"--target", j.sha, "--title", j.tag, "--notes-file", j.path("release-notes.md")}, assets...)...)
	}
	if err == nil {
		releases, err = releasesOf(ctx, j.repo)
	}
	var draft, published any
	if i := slices.IndexFunc(releases, func(r any) bool { return str(r, "tag_name") == j.tag && get(r, "draft") == true }); i >= 0 {
		draft = releases[i]
	} else if err == nil {
		err = fmt.Errorf("gh created no draft release for %s", j.tag)
	}
	if err == nil {
		published, err = runJSON(ctx, gh, ghArgs("-X", "PATCH", fmt.Sprintf("repos/%s/releases/%.0f", j.repo, get(draft, "id")), "-F", "draft=false", "-f", "make_latest=false")...)
	}
	if err != nil {
		return err
	}
	// A draft has only a temporary download address.
	want := "https://github.com/" + j.repo + "/releases/download/" + j.tag + "/" + suseWasmName
	failure := fmt.Sprintf("the published release has no asset at %q, the downloadLocation recorded in the SBOM", want)
	for _, a := range list(published, "assets") {
		if str(a, "browser_download_url") == want {
			failure = ""
		}
	}
	if err := appendEnvFile("GITHUB_STEP_SUMMARY", cmdOut, releaseSummary(j, failure)); err != nil {
		logf("::warning::%s", escapeData(err.Error()))
	}
	if failure != "" {
		return fmt.Errorf("the release %s is published and immutable, but a check after the publication failed. A person must check and fix the release by hand: %s", j.tag, failure)
	}
	return nil
}
