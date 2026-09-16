# SSD Security Framework

Reusable CI/CD security workflows and the gate toolkit they run.

Scanners run before privileged operations, findings normalize into reports, a
policy gate evaluates them fail-closed, and build/deploy blocks on the verdict.
Consumer repositories call these workflows by tag; nothing is copy-pasted, so a
fix made here reaches every repo on the next run.

> `npm install` and `pip install` do not just download packages: they run
> someone else's code on the runner with whatever credentials that runner is
> holding. Therefore, untrusted install/build code must never run in a job that
> holds cloud or deployment credentials.

That principle defines the boundary these workflows enforce.

## What a consumer repository needs

**Nothing from this repository.** No vendored scripts, no copied policy, no
`security/scripts/` directory. Each reusable workflow checks this repository out
itself and places it outside the scanned workspace before any scanner runs.

A consumer provides only:

| File | Why |
| --- | --- |
| `.github/workflows/security.yml` | the thin caller (start from [`examples/`](examples/)) |
| `security/baseline/semgrep-baseline.json` | its own accepted-findings baseline — generated during onboarding, not copied |
| `.gitleaks.toml`, `.trufflehog-exclude-paths.txt` | optional; absent means the scanner's default ruleset, never a skipped scan |
| `security/exemptions.json` | optional; deliberate, owned, expiring exceptions |

`tools/verify-consumer-isolation.sh` proves this claim rather than asserting it,
and runs on every framework PR.

## The workflows

| File | Purpose | Cloud credentials |
| --- | --- | --- |
| `_source-security.yml` | secret scan, dependency scan, SAST, source gate | **none** (break-glass invoker role only, after eligibility) |
| `_image-scan-prepush.yml` | Trivy over a built image tarball + pre-push gate | **none** |
| `_artifact-gate.yml` | policy over a normalized registry report; names no registry | **none** |
| `_ecr-collect.yml` | the ECR adapter: push, poll by digest, normalize | ECR push+scan role |
| `_conformance.yml` | which controls apply here, and what happened to each | **none** |

Swapping registries means writing a sibling collector that emits the same
normalized report. The gate and the policy do not change.

## Quick start

```yaml
jobs:
  source-security:
    uses: IamRitz/ssd-security-framework/.github/workflows/_source-security.yml@v1
    permissions:
      contents: read
      pull-requests: write
    with:
      toolkit_ref: v1          # MUST match the @v1 above
      gate_mode: log-only      # start here; see the rollout sequence
      semgrep_configs: |
        p/owasp-top-ten
        p/javascript
      semgrep_paths: src
```

Do not start at `enforce`. A repo that has never had SAST has a backlog, and
blocking on it the first day is the fastest way to get the pipeline switched
off. The full sequence is in [`docs/onboarding.md`](docs/onboarding.md).

## Capability declaration

Consumer repos differ in what they *ship*, not just how they are configured, so
the framework computes what applies rather than assuming:

```yaml
artifact_type: container | archive | library | none
registry:      ecr | none
deploy_target: framework-gated | self-managed | none
```

A control that does not apply is reported **N/A with a reason** — never skipped
silently, and never called "exempt". The distinction is the point:

- **N/A** is a stable fact about what the repo is. A library will never grow a
  container image to scan.
- **Exempt** is debt: a control that *does* apply, deliberately not enforced,
  carrying an owner and an expiry. It expires closed.

A conformance report that renders both as "skipped" tells a reviewer nothing.

## Documentation

| Document | What it covers |
| --- | --- |
| [`docs/onboarding.md`](docs/onboarding.md) | the full per-repo setup, AWS side included, and the rollout sequence |
| [`docs/workflow-contracts.md`](docs/workflow-contracts.md) | every input, output, and portability rule |
| [`docs/versioning.md`](docs/versioning.md) | what is pinned, what moves, and why they differ by layer |
| [`docs/toolkit-resolution.md`](docs/toolkit-resolution.md) | how the toolkit reaches a consumer that has none of it |
| [`docs/aws-setup.md`](docs/aws-setup.md) | OIDC, IAM, ECR — split by one-time vs per-repo |
| [`docs/break-glass-setup.md`](docs/break-glass-setup.md) | the approval path, and what a repo without Slack gets |

## The gate — three states, fail-closed

`security-gate.mjs` returns **PASS**, **BLOCK**, or **PASS-WITH-EXCEPTIONS**.
EXCEPTION exists for the real middle case: a critical/high dependency finding
with **no fix available** is recorded visibly and allowed, rather than blocking
indefinitely on an upstream patch you do not control. A missing report,
malformed JSON, or a report-integrity failure all **block** — the safe outcome
is always the default.

## Development

```sh
node --test                          # toolkit + workflow structural guards
./tools/verify-consumer-isolation.sh # prove a consumer needs no framework files
```

The toolkit imports **Node builtins only**. That is what lets it drop onto any
runner with nothing installed, and it is asserted in CI.
