# Trivy image provenance

The Trivy scanner image is pinned by digest in `.github/workflows/security.yml`
(the pre-push image scan). This file records how that digest was chosen, so the
pin is traceable rather than trusted blindly — the discipline the March 2026
Trivy supply-chain compromise (GHSA-69fq-xp46-6x23) makes essential.

| Field | Value |
| --- | --- |
| Version | `0.74.0` (released 2026-08-14; ≥ 7-day cooldown observed) |
| Image | `ghcr.io/aquasecurity/trivy` |
| Pinned digest | `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| Pulled from ghcr | 2026-09-10 |
| Explicitly avoided | `0.69.4`, `0.69.5`, `0.69.6`, and `latest` (the compromised/moving tags) |

## Verification status — READ THIS

The review's §5.3 step 3 calls for **cosign keyless** verification of the image
signature before pinning. Attempted on 2026-09-10:

```
cosign verify ghcr.io/aquasecurity/trivy@sha256:62b1e65e... \
  --certificate-identity-regexp 'https://github.com/aquasecurity/trivy/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
# -> Error: no signatures found   (cosign tree: no artifacts attached)
```

**Finding (flagged deviation):** current Trivy releases do **not** attach a
cosign `.sig` to the container image. Trivy has moved to **GitHub build-provenance
attestations** (`actions/attest-build-provenance`), which cosign's tag-based
discovery does not surface. So §5.3's exact command cannot succeed for this image
— not because the image is untrustworthy, but because the verification mechanism
changed.

**Complete the verification with the mechanism Trivy actually uses**, before this
pin is relied on for a real deploy (requires the `gh` CLI, unavailable in the
authoring environment):

```
gh attestation verify \
  oci://ghcr.io/aquasecurity/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 \
  --repo aquasecurity/trivy
```

A passing result confirms the digest was built by Trivy's own release workflow.
Record the date and the `gh` output summary here once run. When bumping the pin
(Renovate/Dependabot per review §C6), repeat this verification and update the
table above.
