package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1" //nolint:gosec // UUID version 5 is defined with SHA-1.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// The document does not name the commit of the run, so a second run gives
// the same document for the same artifact and can keep its attestation.
func suseSBOM(ctx context.Context, j *job) error {
	if j.immutableRef == "" {
		return nil
	}
	created, err := time.Parse(time.RFC3339, str(j.upstream, "published_at"))
	if err != nil {
		return fmt.Errorf("the upstream release %s has no publication time: %w", j.tag, err)
	}
	wasmSum, _ := fileSHA256(j.path(suseWasmName))
	upstreamSum, _ := fileSHA256(j.path(upstreamSBOMName))
	cfg, root, pkg := j.cfg, j.upstreamRoot, "SPDXRef-Package-"+j.id
	j.suseNamespace = cfg.SBOM.NamespaceBase + "/" + j.id + "/" + j.version + "-" + nameUUID(j.immutableRef)
	repository, digest, _ := strings.Cut(j.immutableRef, "@")
	orNoAssertion := func(key string) string { return cmp.Or(str(root, key), "NOASSERTION") }
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": j.id + "-" + j.version,
		"documentNamespace": j.suseNamespace,
		"creationInfo": map[string]any{
			"created":  created.UTC().Format("2006-01-02T15:04:05Z"),
			"creators": []any{"Organization: SUSE", "Tool: " + cfg.SBOM.ToolName},
		},
		"externalDocumentRefs": []any{map[string]any{
			"externalDocumentId": "DocumentRef-upstream", "spdxDocument": j.upstreamNamespace,
			"checksum": map[string]any{"algorithm": "SHA256", "checksumValue": upstreamSum},
		}},
		"packages": []any{map[string]any{
			"SPDXID": pkg, "name": j.id, "versionInfo": j.version, "packageFileName": suseWasmName,
			"checksums":     []any{map[string]any{"algorithm": "SHA256", "checksumValue": wasmSum}},
			"filesAnalyzed": false, "primaryPackagePurpose": "APPLICATION",
			"supplier": cfg.SBOM.Supplier, "originator": cfg.SBOM.Originator,
			"downloadLocation": "https://github.com/" + j.repo + "/releases/download/" + j.tag + "/" + suseWasmName,
			"externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
				"referenceLocator": "pkg:oci/" + j.id + "@" + strings.Replace(digest, ":", "%3A", 1) + "?repository_url=" + repository + "&tag=v" + j.version}},
			"sourceInfo": "Repackaged by SUSE from https://github.com/" + cfg.Upstream.Repository + " release " + j.tag +
				" (upstream OCI digest " + j.upstreamDigest + ", upstream source commit " + cmp.Or(str(root, "versionInfo"), "unknown") +
				"). The WebAssembly code sections are unmodified; the io.kubewarden.metadata custom section was replaced with SUSE provenance annotations.",
			// SUSE did not determine the licenses.
			"licenseConcluded": orNoAssertion("licenseConcluded"), "licenseDeclared": orNoAssertion("licenseDeclared"),
			"copyrightText": orNoAssertion("copyrightText"),
		}},
		"relationships": []any{
			map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": pkg, "relationshipType": "DESCRIBES"},
			map[string]any{"spdxElementId": pkg, "relatedSpdxElement": "DocumentRef-upstream:" + str(root, "SPDXID"), "relationshipType": "GENERATED_FROM"},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The purl holds "&", which must stay as it is.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := os.WriteFile(j.path(suseSBOMName), buf.Bytes(), 0o644); err != nil {
		return err
	}
	if out, err := run(ctx, sbomUtility, "validate", "--input-file", j.path(suseSBOMName)); err != nil {
		return fmt.Errorf("the SUSE SBOM is not valid SPDX 2.3: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// upstreamRoot does not guess, because GENERATED_FROM would then claim a
// provenance that nobody checked. The form of DESCRIBES depends on the tool.
func upstreamRoot(doc any) (any, error) {
	var ids []string
	for _, r := range list(doc, "relationships") {
		if str(r, "relationshipType") == "DESCRIBES" && str(r, "spdxElementId") == "SPDXRef-DOCUMENT" {
			ids = append(ids, str(r, "relatedSpdxElement"))
		}
	}
	for _, id := range list(doc, "documentDescribes") {
		ids = append(ids, str(id))
	}
	slices.Sort(ids)
	if ids = slices.Compact(ids); len(ids) != 1 {
		return nil, fmt.Errorf("the upstream SBOM describes %d packages (%s), but it must describe exactly 1", len(ids), strings.Join(ids, " "))
	}
	for _, p := range list(doc, "packages") {
		if str(p, "SPDXID") == ids[0] {
			return p, nil
		}
	}
	return nil, fmt.Errorf("the upstream SBOM describes %q, but it has no package with that SPDXID", ids[0])
}

// nameUUID returns a version 5 UUID in the URL namespace of RFC 4122.
func nameUUID(name string) string {
	h := sha1.New() //nolint:gosec // UUID version 5 is defined with SHA-1.
	h.Write([]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8})
	h.Write([]byte(name))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	b := hex.EncodeToString(u)
	return b[0:8] + "-" + b[8:12] + "-" + b[12:16] + "-" + b[16:20] + "-" + b[20:32]
}
