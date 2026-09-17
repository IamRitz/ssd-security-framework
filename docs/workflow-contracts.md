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
| `bootstrap_baseline` | boolean | `false` | **Onboarding only.** Evaluate SAST against an empty accepted set because no baseline exists yet, then generate and upload a candidate. Requires `gate_mode: log-only`, and **refuses if a baseline already exists**. See [onboarding §1.1](onboarding.md#11-bootstrap-the-first-semgrep-baseline). |
| `synthetic_block_fixture` | string | `none` | Demo only. Requires an **isolated** break-glass configuration and can never fall through to production — dev URLs for `http`, the `synthetic_break_glass_*` inputs for `lambda`. |
| `synthetic_break_glass_lambda_function` | string | `''` | Test broker used only for a synthetic `lambda` run. **Must differ from** `break_glass_lambda_function`. |
| `synthetic_break_glass_lambda_role_arn` | string | `''` | Test invoker role for a synthetic `lambda` run. **Must differ from** `break_glass_lambda_role_arn`, so a fabricated BLOCK cannot assume the production role. |
| `synthetic_break_glass_aws_region` | string | `''` | Region of the test broker. Falls back to `break_glass_aws_region`. |

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
| `secret_scan_result` | Secret scanning control — `success` \| `failure` \| `cancelled` \| `skipped` \| `untrusted` (since v1.1.x) |
| `dependency_scan_result` | Dependency scanning control — same vocabulary (since v1.1.x) |
| `sast_result` | SAST control — same vocabulary (since v1.1.x) |
| `source_gate_result` | Source security gate control — the `source-gate` job's own status: `success` \| `failure` \| `cancelled` (since v1.1.x) |

`gate_mode` is echoed back deliberately: a caller that reports the mode it
*believes* it passed can display "enforce" while the gate ran in log-only.

### Per-control results: scanning is not the same as passing policy

A caller's `needs.source-security.result` is the **aggregate** of four jobs. When
the gate BLOCKs, it is `failure` — even though every scanner ran and produced a
usable report. Feeding that one value to all four conformance controls reports
three working scanners as failed. The per-control outputs exist so that never
happens: **use them for conformance, and keep the aggregate for the required
`security-gate` check**, which really is "did this PR pass".

Two different questions, answered separately:

| Control kind | Question | `success` means | Not a failure |
| --- | --- | --- | --- |
| scanning (`secret_scan_result`, `dependency_scan_result`, `sast_result`) | did the scanner **execute and produce trustworthy evidence**? | the scanner job succeeded — it validates its own report before upload — and the gate did not reject that report | **findings**. A scanner that finds vulnerabilities has done its job. |
| gate (`source_gate_result`) | did that evidence **satisfy security policy**? | the gate job finished without an enforced BLOCK | — |

Scanning result values:

| Value | Meaning |
| --- | --- |
| `success` | trustworthy report produced — **not** "no vulnerabilities found" |
| `failure` | the scanner job failed (crash, unexpected exit status, missing/empty/malformed report): findings are UNKNOWN |
| `cancelled` / `skipped` | the scanner job did not complete / did not run |
| `untrusted` | the scanner job succeeded, but the gate attributed a report-integrity failure **to this control's report** (`integrity.failures[].control`): findings are UNKNOWN |

How each value is derived, and how it fails closed:

- Each scanning result comes from **that scanner job's own result** (`needs.<job>.result`
  inside `source-gate`), never from the aggregate, and is downgraded to `untrusted`
  only by an integrity failure the gate attributed to that control. A BLOCK verdict
  downgrades nothing.
- An integrity failure in the gate's **own** inputs — the policy, the Semgrep
  baseline — is attributed to `source-gate` and blames no scanner. The gate stops at
  the first uninterpretable input, so only that one is attributed; the other reports
  were validated by their own scanner jobs before upload.
- If the per-control step cannot run its script, it publishes `failure` for every
  scanning control. `source_gate_result` is published by the job's **last** step from
  `job.status`, which already reflects the enforcement step. If the `source-gate` job
  is skipped, or cancelled before those steps, the outputs are **empty**: a consumer
  must treat empty as missing evidence (conformance reports it `failed`), never as
  success.
- `source_gate_result` is `success` for a BLOCK in `log-only` (reported, not
  enforced) and for a BLOCK overridden by a verified break-glass approval. Pass
  `verdict`, `gate_mode` and `integrity_trusted` alongside it (see `_conformance.yml`)
  so the report says which.

### Scanner exit status is data

pip-audit and OSV-Scanner exit **1 when they find vulnerabilities**. Those steps
used to run under `continue-on-error`, which painted GitHub's red "Process
completed with exit code 1" on a working scan *and* hid a genuine crash the same
way. They now capture the exit status and judge it together with the report
(`check-scanner-exit.mjs`):

| Exit | Report | Step |
| --- | --- | --- |
| 0 | valid, no findings | passes — clean |
| 1 | valid, **≥ 1** finding | passes — findings found (a `::notice::`, not an error) |
| 0 | valid, findings present | passes — every finding is still in the report and evaluated by the gate |
| 1 | valid, **no** findings | **fails** — the scanner signalled something the report does not show |
| any other (OSV 127/128, docker 125, …) | any | **fails** — scanner or container failure |
| any | missing, empty, or malformed | **fails** — findings UNKNOWN, not clean |

**Known limitation — pip-audit.** pip-audit (verified in the pinned 2.10.1) exits 1
both for "vulnerabilities found" and for fatal errors, so its exit code alone cannot
distinguish them. The report does: a fatal error exits before any report is written,
so it fails as an empty/unparseable report. A crash occurring *after* a complete,
well-formed report was written would be indistinguishable; no such path exists in
the pinned version. OSV-Scanner reserves distinct codes, so its failures are also
caught by status. npm audit keeps its existing handling: its error output is
recognised in the report (`error`), and it never used exit status as a signal here.

### Scanner image acquisition is separate from scanner execution

The SAST step runs Semgrep in three phases (`scanner-execution.mjs`):

| Phase | What | Retried |
| --- | --- | --- |
| acquire | `docker pull` of the **pinned digest** (an image already on the runner is used as is) | **yes**, only for a registry failure its error text shows to be transient (`registry-network`, `registry-rate-limit`): at most **3 attempts**, waiting 5 s then 10 s, each attempt logged as `attempt N/3`. Auth, not-found and unrecognized failures fail at once. |
| run | `docker run --pull=never` of the already-acquired image, exactly once | **never** — a crash, invalid rule config, OOM or any non-zero exit fails the step |
| complete | judge the exit status and the report | no — non-zero exit, missing report or invalid report fails the step |

Nothing is masked (`|| true`, `continue-on-error`), the image identity is fixed by
digest (no tag, no `:latest`, no mirror), and a failure in any phase still leaves
no trustworthy `semgrep.json`, so the gate still fails closed. Each phase writes
`reports/scanner-execution-semgrep.json`, which `sast-reports` uploads even on
failure; the gate copies it into `security-gate.json` → `scannerExecution`
([evidence-model.md](evidence-model.md#scanner-execution-evidence)). The record
never affects a verdict.

The Secret scanning job likewise validates both reports before upload, so all three
scanning jobs' `success` means the same thing. Both are deliberate tightenings in the
fail-closed direction: a malformed secret report, or an exit-1-with-no-findings, used
to surface only as a gate integrity BLOCK and now also fails the scanner job itself.

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
    "package": "openssl", "fixedVersion": "3.3.2-r0",  // optional context
    // Optional scanner evidence (since v1.1.x), used only for developer
    // guidance and never for a decision: the scanner's own severity and fix
    // value beside the framework's interpretation of them, and per-package fixes.
    "scannerSeverity": "UNTRIAGED", "fixAvailability": "PARTIAL",
    "packages": [{ "name": "openssl", "version": "3.3.1-r0", "fixedInVersion": "3.3.2-r0" }]
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
| `phase` | string | `pr` — `pr` \| `delivery`. Which part of the lifecycle THIS run is. |
| `break_glass_enabled` | boolean | `false` |
| `observed` | string (JSON) | **required** — control id → `{status, evidence}`, optionally with gate evidence `verdict`, `gate_mode`, `integrity_trusted` |
| `exemptions_path` | string | `security/exemptions.json` |

| Output | Meaning |
| --- | --- |
| `failed` | applicable, expected-now, non-exempt controls that did not pass |
| `deferred` | required by the repo but not run in this phase — **proven elsewhere, not coverage here** |
| `not_applicable` | controls the declared capabilities exclude |
| `exempt` | controls carrying a live exemption — **debt, not coverage** |

### Capability is not the same as lifecycle

The report answers two different questions, and conflating them is how a pull
request ends up claiming a deploy succeeded:

1. **What does this repository require?** — every control with
   `appliesToRepository: true`, regardless of phase.
2. **What executed successfully in this run?** — every control with status
   `applied`.

Five statuses, deliberately distinct:

| Status | Meaning |
| --- | --- |
| `applied` | ran in this phase, real result recorded |
| `deferred` | required by the repo, but does not run in this phase — proven by the other run, never reported as a pass |
| `not-applicable` | the declared capabilities give it no subject, with a reason naming the capability |
| `exempt` | applies, deliberately unenforced; carries an owner and an expiry, and **expires closed** |
| `failed` | applies, was expected now, and did not pass — including producing no evidence at all |

Only `failed` fails the job. `deferred` does not, because the control genuinely
runs elsewhere; that is why the delivery caller must actually exist and run.

Control phases:

| Control | Phase(s) |
| --- | --- |
| `secret-scan`, `dependency-scan`, `sast`, `source-gate` | `pr`, `delivery` |
| `image-scan-prepush` | `pr`, `delivery` — the point is catching it *before* any push |
| `break-glass` | `pr`, `delivery` |
| `registry-scan-collect`, `artifact-gate`, `gated-deploy` | `delivery` only |

Unrecognized or self-contradictory capability values **fail closed**. A typo like
`containr` must not silently degrade to "none", because that would mark the image
controls N/A and report a green conformance for an unscanned image. An
unrecognized `phase` is rejected for the same reason: silently defaulting to `pr`
would defer every delivery control and report a green run.

A control that applies, runs in this phase, and appears in neither `observed` nor
the exemptions is **failed**: absence of evidence is not evidence the control ran.
Supplying evidence for a control this phase does not run produces a **warning**
and is not honoured.

### What a result means depends on the kind of control

Each control has a `kind` (recorded in the report), and the reason printed for a
failure is derived from it and from whatever evidence the caller supplied — never
just "observed result 'failure'":

| Kind | Controls | A failure means |
| --- | --- | --- |
| `scan` | `secret-scan`, `dependency-scan`, `sast` | no trustworthy report exists (`failure`, `cancelled`, `skipped`, `untrusted`). **Findings never fail a scanning control.** |
| `gate` | `source-gate`, `image-scan-prepush`, `artifact-gate` | the evidence did not satisfy policy, or the gate itself failed |
| `delivery` | `registry-scan-collect`, `gated-deploy` | the delivery step did not complete |
| `approval` | `break-glass` | the approval channel is not in place |

Optional gate evidence in an `observed` entry, used only to explain:

| Field | Effect |
| --- | --- |
| `verdict` | `failure` + `BLOCK`/`BLOCK_DEPLOY` → "*the source security policy gate returned a blocking result (verdict BLOCK)*". `failure` with a non-blocking verdict → the gate job errored. `success` + `BLOCK` → applied, noting the BLOCK was not enforced (log-only) or was overridden. |
| `gate_mode` | distinguishes "not enforced (log-only)" from a break-glass override |
| `integrity_trusted` | `false` + BLOCK → "*failed closed: a scan report could not be trusted*" rather than a policy BLOCK |

An empty or unrecognized `status` is `failed` with that stated as the reason.
Applied controls carry a `detail` (e.g. *policy verdict PASS*), and the summary
reads: *requires N controls. In this run: A applied (executed successfully), F
failed, D deferred to another phase, E exempt.* The report's `schemaVersion` stays
2: `kind`, `detail`, `observedStatus` and `verdict` on a control are optional
additions.

For the live source-only run where all three scanners succeeded and the gate
BLOCKed, the per-control wiring reports:

| Control | Status | Why |
| --- | --- | --- |
| Secret scanning | ✅ applied | scanner executed and produced trustworthy evidence |
| Dependency scanning | ✅ applied | scanner executed and produced trustworthy evidence |
| SAST | ✅ applied | scanner executed and produced trustworthy evidence |
| Source security gate | ❌ failed | the source security policy gate returned a blocking result (verdict BLOCK) |

## `gate_mode`

| Mode | Blocking verdict | Slack | Use |
| --- | --- | --- | --- |
| `enforce` (default) | fails the job | on BLOCK, unless an interactive break-glass request for it was delivered | Steady state |
| `log-only` | reported, job passes | never | Onboarding |

Log-only messages depend on the verdict, on every surface (gate job annotations,
the shipped `security-gate` aggregate, the conformance job, the PR comment):

| Situation | Message (gist) |
| --- | --- |
| PASS / DEPLOY + `log-only` | *verdict PASS. gate_mode=log-only; no blocking verdict exists, so nothing was suppressed* — plus a reminder that log-only is a rollout mode. Never "not enforced", never "GREEN BY CONFIGURATION". |
| BLOCK / BLOCK_DEPLOY + `log-only` | *verdict BLOCK, but gate_mode=log-only so the BLOCK is reported and NOT enforced*; the aggregate keeps **GREEN BY CONFIGURATION, not by verdict** |
| verdict unavailable + `log-only` | nothing is enforced; treat the run as UNKNOWN, not clean |
| BLOCK + `enforce` | the job fails (unchanged) |

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

## Developer feedback: every statement is observed state

One normalized report (`format-findings.mjs`) feeds all three surfaces — Slack,
the PR comment, and `$GITHUB_STEP_SUMMARY` — so they cannot disagree. Every
sentence in it must be backed by something the gate recorded or the workflow
observed. Where a value is the framework's own interpretation, it says so: a
pip-audit advisory is "classified high by the framework (fail-closed)", never
"pip-audit reported high"; a Semgrep rule is linked to the Registry only when
its own `metadata.source` says it came from there, never because its id is
dotted (a local rule file's directory becomes a dotted id prefix too).

### Break-glass: eligibility is not invocation

Five facts are kept distinct, and no later one is inferred from an earlier one:

| Fact | Evidence |
| --- | --- |
| **eligible** | the gate result's `breakGlass.eligible` (policy) |
| **enabled** | the `break_glass_enabled` input |
| *requestPathEntered* (internal) | the eligibility-check step succeeded — proves only that the approval path began |
| **requested** | the **Request break-glass decision** step itself ran (a later transport or credential step can stop the path before it) |
| **delivered** | the request step succeeded: the broker accepted a pending request |
| **decision** | the poll step's outcome (the same signal the enforce step uses) plus `break-glass-decision.json`: `approved`, `denied`, `expired`/`timeout`, or `decision-unavailable` |

The workflow hands the notifier `BREAK_GLASS_ENABLED` and each break-glass
step's `outcome`. A step whose condition was false reports `skipped`, so a
disabled, failed, or never-entered request is never described as sent. A
notifier given no state at all claims nothing.

| Situation | What developers read | Plain BLOCK Slack alert |
| --- | --- | --- |
| eligible, break-glass disabled | eligible by policy, **not enabled** for this repo; no request made | **sent** |
| enabled, BLOCK not eligible | not eligible: includes a never-overridable finding | sent |
| eligible, path stopped before the request step | no request was attempted; **no override is active** | sent |
| eligible, request step ran and failed | request attempted but not confirmed delivered; **no override is active** | sent |
| request delivered, then approved / denied / timed out | entered review, request sent; then the decision | suppressed — the interactive request already reached approvers |
| `gate_mode: log-only` | eligible by policy, but log-only enforces nothing; no request made | suppressed (log-only) |

Routing chooses surfaces only; it never changes the verdict.

### Scan unavailable is not a policy BLOCK

When every blocking finding is a report-integrity failure, the headline says
**`BLOCK — scan unavailable`** (no trustworthy report was produced: the job failed,
or the execution record shows acquisition/execution failure or a missing report)
or **`BLOCK — scan untrusted`** (a report exists but could not be interpreted), and
states *This is not a vulnerability-policy BLOCK*. The summary then shows scan
health per control, **Security state: UNKNOWN**, the execution record's cause, a
suggested action chosen from that cause (e.g. *Re-run the failed jobs. If the
failure repeats, investigate scanner registry/network availability.* for
`registry-network`), and *Do not generate a baseline from this run.* The verdict,
`integrity_trusted`, routing and break-glass ineligibility are unchanged. The
notifier receives each scanner job's result (`*_JOB_RESULT`) so scan health uses
the same derivation as the per-control outputs.

### The summary is bounded triage; full evidence is in artifacts

The job summary and PR comment render gate status, scan health, counts, one
compact row per unique issue, conflict callouts, and collapsible full cards for
BLOCK / EXCEPTION / REVIEW only, within fixed limits that state every omission
exactly. REVIEW and INFO are presentation labels for LOG issues and never change
policy. `security-gate.json` stays complete, and `security-gate-evidence.md`
(uploaded with it; `image-gate-evidence.md` / `image-gate-prepush-evidence.md` for
the image gates) holds every issue's full card. Details:
[evidence-model.md § Presentation](evidence-model.md#presentation-a-triage-view-over-this-model).

### Reproduce commands match what the run scanned with

With no `reproduce_commands` override, the command is built from this run's own
configuration: every configured Semgrep config and path, the Gitleaks config and
TruffleHog exclude-paths file when present, the scanned image tarball for Trivy,
and `aws ecr describe-image-scan-findings` for the exact digest for registry
findings. When the configuration is not known, a finding gets **no** command
rather than one that would not reproduce it. Integrity failures get none — there
is no finding to reproduce.

### The PR comment: not applicable, not permitted, or failed

| Outcome | Meaning | Notifier step |
| --- | --- | --- |
| not applicable | no PR for this run (`push`, `schedule`, `workflow_dispatch` without `pr_number`, the post-push artifact gate) | expected — logged, not a failure |
| fork read-only | HTTP 403 on a fork PR: `pull_request` gives fork code a read-only token by design | expected — explained in the job summary |
| permission | HTTP 403 on a same-repo PR, or no token: the caller did not grant `pull-requests: write` | failure (the step is `continue-on-error`) |
| API failure | anything else | failure |

### Correlated issues: raw findings versus what a developer fixes

Scanners overlap. In the live run that motivated this, one `requests`
vulnerability arrived as pip-audit `PYSEC-2026-2275` (BLOCK — pip-audit reports no
severity, so the framework classifies it high, fail-closed) **and** as OSV-Scanner
`PYSEC-2026-2275` and `GHSA-gc5v-m9x4-r6x2` (both LOG, CVSS-derived medium), all
aliasing `CVE-2026-25645`. It rendered as "1 blocking, 2 logged" for one thing to
upgrade.

There are now two layers, kept apart on purpose:

| Layer | Where | What it is |
| --- | --- | --- |
| **raw findings** | `security-gate.json` → `findings`, `summary` | one entry per scanner record. The policy input and output. **Unchanged**: every record keeps its source, severity derivation, policy rule, action and break-glass eligibility. The verdict is computed from these alone. |
| **issues** | `security-gate.json` → `correlation` (additive, `schemaVersion: 1`) | a grouping for people. Each issue lists the indexes of the raw findings it covers. |

Records correlate **only** when identity is evidenced: same package-scoped source
(pip-audit — always PyPI — or OSV-Scanner with a recorded ecosystem), same
ecosystem, same package (PyPI names compared per PEP 503, all others exactly), and
advisory identifiers connected through each record's own `id` and `aliases`. The
alias graph is an equivalence relation, so a chain A→B→C is one issue. Two
unrelated advisories on one package stay separate; the same advisory on a
different package or ecosystem stays separate. npm audit (one entry per package,
no advisory id), secrets, SAST, image findings and integrity failures are never
merged.

An issue's `action` is the **strongest** action among its records
(BLOCK_DEPLOY/BLOCK > EXCEPTION > LOG); `actions` lists every underlying action.
The least severe interpretation is never chosen, and nothing is averaged.

```jsonc
"correlation": {
  "schemaVersion": 1,
  "summary": { "issues": 2, "rawFindings": 5, "block": 1, "exception": 0, "log": 1, "integrity": 0 },
  "issues": [{
    "key": "PyPI:requests:0", "correlated": true, "action": "BLOCK", "actions": ["BLOCK", "LOG"],
    "findings": [0, 1, 2], "sources": ["pip-audit", "osv-scanner"],
    "package": "requests", "ecosystem": "PyPI", "installedVersions": ["2.32.5"],
    "primaryId": "CVE-2026-25645",
    "advisoryIds": ["CVE-2026-25645", "GHSA-gc5v-m9x4-r6x2", "PYSEC-2026-2275"],
    "highestSeverity": "high", "breakGlassEligible": true
  }]
}
```

**Counts.** Two numbers, both defined, neither silently replacing the other:

- `summary.block` / `.exception` / `.log` — **raw finding counts**, one per scanner
  record. Unchanged in meaning; the documented contract.
- `correlation.summary.block` / `.exception` / `.log` / `.integrity` — **unique
  issue counts** by each issue's strongest action; `issues` is their total and
  `rawFindings` the number of records they were built from.

The PR comment, job summary and Slack headline **unique issues**, and state the raw
count beside them whenever correlation merged anything (*1 blocking · 0 exception ·
1 logged — 2 unique issues from 5 scanner findings*). A correlated issue renders as
one card listing every record — scanner, id, action, and that record's own severity
derivation — plus all advisory ids and fixed versions with the scanners that list
them.

**Dependency evidence.** Every package-scoped issue also carries `evidence`:
the dependency **relationship** (`direct` / `transitive` / `unknown`, with its
basis) and the **version resolution** (`consistent` / `conflicting` / `unknown`,
with every scanner's and manifest's observation and a deterministic
confidence), backed by a run-level `dependencyEvidence` record. Relationship and
effective version are separate from the advisory match and from the policy
action. The feedback states a conflict rather than headlining one scanner's
version, and offers a pin command only for a proven direct dependency whose
evidence agrees. Nothing here is read by a policy decision. The full schema,
rules, wording and known limits are in [evidence-model.md](evidence-model.md).

### Gate result fields added for guidance (additive, optional)

`security-gate.json` findings may carry: `registryUrl` and `scannerSeverity`
(Semgrep); `ruleDescription` (Gitleaks); `location` and `verificationErrored`
(TruffleHog); `fixPackage`, `fixIsSemVerMajor`, `viaPackages` (npm audit);
`severitySource`, `installedVersion`, `fixVersions`, `aliases`, `ecosystem`
(pip-audit / OSV-Scanner); `correlation` (see above), whose package-scoped issues
carry `evidence`; `dependencyEvidence`, the run-level record behind it
([evidence-model.md](evidence-model.md)); `scannerExecution`, the scanner
execution records (present on every source gate result, including a
report-integrity one); and, on a report-integrity
failure, `control` on the finding and on `integrity.failures[]` naming the control
whose input could not be interpreted (`secret-scan`, `dependency-scan`, `sast`,
`source-gate`). Image gate findings may carry `scannerSeverity`,
`installedVersion`, `target`, `fixAvailability`, `packages`. None is read by any
decision, fingerprint, or baseline; existing fields keep their meaning.

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
