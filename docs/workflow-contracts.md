# Reusable workflow contracts

These contracts are the interface every consumer reads. Changing one breaks
every consumer at once, so treat them as a published API: **add inputs with
defaults; never rename or repurpose an existing one.**

## Common inputs

Every reusable workflow accepts these. They control how the toolkit is loaded —
see [toolkit-resolution.md](toolkit-resolution.md).

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `toolkit_repository` | string | `IamRitz/ssd-security-framework` | Framework repo holding `policy.yaml` and `scripts/`. |
| `toolkit_ref` | string | `v1` | Ref the toolkit is checked out at. **Must match the `@ref` of the `uses:` line.** Empty is refused — it would resolve to a default branch. |
| `toolkit_path` | string | `''` | Escape hatch: a toolkit already vendored in the caller's checkout. When set, no framework checkout happens. |
| `node_version` | string | `24.21.0` | Node for the `.mjs` gate scripts. A **tool** dependency, not an assumption about the consumer's language. |
| `gate_mode` | string | `enforce` | `enforce`: a blocking verdict fails the job. `log-only`: reported, nothing fails, no Slack. |
| `policy_path` | string | `''` | Consumer-owned `policy.yaml`. Empty uses the framework's default, which travels with the toolkit and is therefore centrally fixable. (`_ecr-collect.yml` makes no policy decision and does not accept this.) |

## `_source-security.yml`

Secret scan, dependency scan, SAST, and the source gate. Assumes no cloud role
except the narrowly scoped break-glass invoker, and only after eligibility is
confirmed.

| Input | Type | Default | Meaning |
| --- | --- | --- | --- |
| `semgrep_configs` | string | `p/owasp-top-ten` | Whitespace/newline separated configs. Add your language pack. |
| `semgrep_paths` | string | `.` | Whitespace separated scan paths. |
| `semgrep_baseline_path` | string | `security/baseline/semgrep-baseline.json` | **Consumer-owned.** Separates new findings from the existing backlog. |
| `gitleaks_config` | string | `.gitleaks.toml` | Omitted automatically when absent — the scan still runs with the default ruleset. |
| `trufflehog_exclude_paths` | string | `.trufflehog-exclude-paths.txt` | Omitted automatically when absent. |
| `reproduce_commands` | string (JSON) | `''` | Maps finding source → the local command a developer runs. Empty uses portable direct scanner invocations. |
| `slack_notify_url` | string | `''` | Incoming webhook for BLOCK alerts. Empty disables Slack. |
| `pr_number` | string | `''` | PR receiving the findings comment. Defaults to the PR of a `pull_request` run. |
| `break_glass_enabled` | boolean | `false` | Whether an eligible BLOCK may enter the approval flow. |
| `break_glass_transport` | string | `http` | `lambda` (OIDC, no secret) or `http` (legacy webhook + HMAC). |
| `break_glass_lambda_role_arn` / `_function` / `_aws_region` | string | `''` | Required together when transport is `lambda`. |
| `break_glass_notify_url` / `_status_url` | string | `''` | Legacy HTTP transport endpoints. |
| `break_glass_timeout_seconds` | string | `''` | How long to wait for a verified decision. |
| `synthetic_block_fixture` | string | `none` | Demo only. Refuses to run unless **both** break-glass URLs are passed explicitly, so a synthetic BLOCK can never reach production endpoints. |

### Secrets

| Secret | Required | Meaning |
| --- | --- | --- |
| `break_glass_shared_secret` | no | HMAC key for the legacy HTTP break-glass channel. |

This is the **only** secret any reusable workflow accepts, it is declared
explicitly, and it is not a cloud credential. The `lambda` transport needs no
secret at all. `_image-scan-prepush.yml`, `_artifact-gate.yml` and
`_conformance.yml` declare no `secrets:` block whatsoever — they cannot receive
one. **Callers must never use `secrets: inherit`.**

### Outputs

| Output | Values |
| --- | --- |
| `verdict` | `PASS` \| `PASS-WITH-EXCEPTIONS` \| `BLOCK` |
| `break_glass_eligible` | `true` when the BLOCK consists only of eligible findings |
| `gate_mode` | the mode this run actually evaluated under, echoed back |
| `integrity_trusted` | `false` when a scanner could not interpret its input — findings are UNKNOWN, not clean |

`gate_mode` is echoed back deliberately: a caller that reports the mode it
*believes* it passed can display "enforce" while the gate ran in log-only.

## `_image-scan-prepush.yml`

Trivy plus the pre-push gate, over an image tarball the caller already built.
Assumes no cloud role, accepts no secrets, touches no registry.

| Input | Type | Default |
| --- | --- | --- |
| `image_artifact` | string | **required** |
| `image_tarball` | string | `application-image.tar` |
| `reproduce_commands`, `slack_notify_url`, `pr_number` | string | `''` |

| Output | Values |
| --- | --- |
| `verdict` | `DEPLOY` \| `DEPLOY-WITH-EXCEPTIONS` \| `BLOCK_DEPLOY` |
| `image_id` | Trivy `Metadata.ImageID` — the config digest anchoring the digest chain |
| `gate_mode` | the mode actually evaluated under |
| `integrity_trusted` | `false` on a Trivy false clean (no OS family, no `os-pkgs`) or an EOL base image |

## `_artifact-gate.yml`

Policy over a **normalized** registry scan report. Registry-neutral: it names no
registry and calls no registry API. Assumes no cloud role, accepts no secrets.

| Input | Type | Default |
| --- | --- | --- |
| `report_artifact` | string | **required** |
| `report_path` | string | `reports/registry-image-scan.json` |
| `expected_digest` | string | **required** — a mismatch fails closed |

| Output | Values |
| --- | --- |
| `verdict` | `DEPLOY` \| `DEPLOY-WITH-EXCEPTIONS` \| `BLOCK_DEPLOY` |

### Normalized report schema (the collector → gate contract)

Any collector must emit this shape; `image-gate.mjs` fails closed on anything
else.

```jsonc
{
  "schemaVersion": 1,
  "source": "aws-ecr-basic",     // or "aws-ecr-enhanced"; nothing else is admitted
  "scanStatus": "COMPLETE",
  "image": { "repository": "...", "imageTag": "...", "imageDigest": "sha256:..." },
  "findings": [{
    "id": "CVE-...",
    "severity": "critical|high|medium|low",
    // fix-aware sources only, and REQUIRED there: a missing or non-boolean value
    // is a report-integrity BLOCK_DEPLOY, never a default to "no fix".
    "fixAvailable": true,
    "package": "openssl", "fixedVersion": "3.3.2-r0"   // optional context
  }],
  "severityCounts": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
}
```

`severityCounts` must agree with `findings` exactly — a mismatch is a
report-integrity `BLOCK_DEPLOY`, not a warning.

`image-gate.mjs` admits normalized sources by **explicit entry** in a
`REGISTRY_SOURCES` table that declares whether each is fix-aware. A new
collector is admitted by adding an entry, never by loosening the check.

## `_ecr-collect.yml`

The ECR adapter, and the only workflow here that holds cloud credentials. It
pushes, polls the scan **by digest**, and normalizes. It makes no policy
decision.

| Input | Type | Default |
| --- | --- | --- |
| `image_artifact`, `local_image_ref`, `expected_image_id` | string | **required** |
| `role_arn`, `aws_region`, `ecr_repository`, `immutable_tag` | string | **required** |
| `image_tarball` | string | `application-image.tar` |
| `extra_tags` | string | `''` |
| `report_artifact` | string | `registry-image-scan` |

| Output | Meaning |
| --- | --- |
| `registry` | ECR registry host pushed to |
| `image_digest` | immutable pushed manifest digest |
| `report_artifact` / `report_path` | what to hand `_artifact-gate.yml` |

**Both ECR scanning modes are supported**, detected from the response rather
than configured:

| | Basic | Enhanced (Inspector) |
| --- | --- | --- |
| Findings array | `imageScanFindings.findings[]` | `enhancedFindings[]` — **and** an empty `findings: []` alongside it |
| Fix availability | not reported | `fixAvailable` |
| Normalized `source` | `aws-ecr-basic` | `aws-ecr-enhanced` |

Because an enhanced body carries an empty *basic* findings array, a basic-only
parser reads it as a clean scan — which is how a CRITICAL + 4 HIGH image once
deployed. Two guards prevent it: the mode is derived from which arrays are
populated (both populated is ambiguous and fails closed), and the parsed
findings must reproduce ECR's own `findingSeverityCounts` exactly, per severity.
A `PENDING` body has no counts at all, so a not-yet-started scan can never read
as a complete clean scan.

## `_conformance.yml`

Which controls apply to this repository, and what happened to each.

| Input | Type | Default |
| --- | --- | --- |
| `artifact_type` | string | `none` — `container` \| `archive` \| `library` \| `none` |
| `registry` | string | `none` — `ecr` \| `none` |
| `deploy_target` | string | `none` — `framework-gated` \| `self-managed` \| `none` |
| `break_glass_enabled` | boolean | `false` |
| `observed` | string (JSON) | **required** — control id → `{status, evidence}` |
| `exemptions_path` | string | `security/exemptions.json` |

| Output | Meaning |
| --- | --- |
| `failed` | applicable, non-exempt controls that did not pass |
| `not_applicable` | controls the declared capabilities exclude |
| `exempt` | controls carrying a live exemption — **debt, not coverage** |

Unrecognized or self-contradictory capability values **fail closed**. A typo like
`containr` must not silently degrade to "none", because that would mark the image
controls N/A and report a green conformance for an unscanned image.

A control that applies but appears in neither `observed` nor the exemptions is
**failed**: absence of evidence is not evidence the control ran.

## `gate_mode`

| Mode | Blocking verdict | Slack | Use |
| --- | --- | --- | --- |
| `enforce` (default) | fails the job | on BLOCK | Steady state |
| `log-only` | reported, job passes | never | Onboarding |

`log-only` suppresses **every** failure, including a fail-closed
report-integrity BLOCK. That is the point of the onboarding phase, and it is why
it must not outlive it.

### log-only is a merge bypass, and what contains it

A caller workflow is app-team-owned and edited by ordinary pull request, so
`gate_mode: log-only` is a one-line change that turns a red required check
green. Three things contain that, none of which is the mode itself:

1. **The mode is visible on the PR.** The required context `security-gate` has a
   **constant** name — branch protection matches by exact string, so a name that
   varied with the mode would stop matching in one mode and the rule would
   silently protect nothing. Mode visibility lives in a second, deliberately
   **non-required** check whose name *does* vary (`gate-mode: LOG-ONLY (gate NOT
   enforcing)`). It reads the mode from the reusable workflow's echoed output,
   not from the repo variable, so an edit to the caller cannot show "enforce"
   while running log-only.
2. **An untrusted scan can never become a baseline.**
   `generate-semgrep-baseline.mjs` hard-fails unless every supplied gate result
   reports `integrity.trusted: true`, and CI writes `DO-NOT-BASELINE.txt` into
   the reports artifact in **every** mode.
3. **CODEOWNERS** on the callers, the baseline, and the exemptions file —
   advisory until branch protection requires Code Owner review.

## Portability rules

- **Semgrep rulesets are an input.** A hardcoded language pack on a repo of
  another language reports near-zero findings, which reads as a clean pass. The
  workflow refuses an empty ruleset or an empty scan path rather than reporting a
  scan of nothing.
- **Ecosystem detection is inside the workflow.** npm audit runs only with a
  `package-lock.json`, pip-audit only with a `requirements.txt`. Neither present
  is a clean skip; OSV-Scanner always runs and covers every ecosystem's
  lockfiles, so a Go/Rust/Java repo is still scanned rather than silently
  unscanned.
- **Node is a tool dependency.** Every job that runs a `.mjs` script sets up Node
  explicitly; a pure-Python consumer needs none of its own. The toolkit imports
  **Node builtins only** — asserted in the framework's CI.
- **A Semgrep baseline is a required onboarding artifact.** A missing baseline is
  a fail-closed report-integrity BLOCK, not a pass.
- **Artifact scanning is genuinely optional.** A repo shipping a library, a
  static site, or a Lambda zip calls only `_source-security.yml` and declares its
  `artifact_type`; the image controls are then reported N/A with a reason.
- **Developer guidance carries no repo-specific tooling.** The notifier's
  "Reproduce locally" line defaults to a direct scanner invocation, never
  `make sast`. Malformed override JSON falls back to the defaults rather than
  failing a run — this is guidance, never a gate input.
