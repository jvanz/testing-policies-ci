This is a SUSE repackage of the upstream Kubewarden policy
`pod-privileged-policy` 1.2.3.

The WebAssembly module comes from the upstream release pipeline. The workflow
checked its signature and pulled it by digest. Then kwctl annotate replaced
the provenance metadata and wrote the module out again. The workflow signed
the result with the identity of this repository.

| | |
|---|---|
| Upstream release | [pod-privileged-policy/v1.2.3](https://github.com/kubewarden/policies/releases/tag/pod-privileged-policy/v1.2.3) |
| Verified source | `ghcr.io/kubewarden/policies/pod-privileged@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| Published artifact | `ghcr.io/rancher/suse-security-policies/pod-privileged@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` |
| Upstream source code | `upstream-source.tar.gz`, commit [`cccccccccccccccccccccccccccccccccccccccc`](https://github.com/kubewarden/policies/tree/cccccccccccccccccccccccccccccccccccccccc), sha256 `eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` |

## Changelog

## Fixes

- Fix kubewarden/policies#12 and kubewarden/other#3, thanks `@alice`.
- Mail a@b.com, keep `@code` and a.b#1.
