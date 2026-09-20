# `ssd-onboard`: configuration-driven onboarding

`ssd-onboard` generates and maintains a consumer repository's security (and,
for framework-gated delivery, deployment) workflows from one reviewed,
**non-secret** file: `.ssd/onboarding.yml`. It replaces copying an example and
hand-editing YAML.

Design record and gap analysis: [onboarding-architecture.md](onboarding-architecture.md).
The manual procedure it automates: [onboarding.md](onboarding.md).

> **Phase 1 boundary.** `ssd-onboard` edits files in the consumer repository and
> nothing else. It makes **no AWS calls** and **no GitHub mutations**: it runs
> `git` read-only and, for `baseline prepare --run`, `gh api` (GET) and
> `gh run download` behind an allowlist. The `aws` and `github` commands are
> designed (architecture doc, Parts D–E) but not implemented, and exit 2.

## Obtaining ssd-onboard

The CLI is not published as a package. It is the `onboarding/` directory of the
framework, and it **must run from a clean git checkout of the framework at
exactly the commit the consumer pins** (`framework.ref`):

```sh
git clone https://github.com/IamRitz/ssd-security-framework ssd-framework
git -C ssd-framework checkout --detach <reviewed-40-char-sha>
git -C ssd-framework rev-parse HEAD          # must print that SHA
git -C ssd-framework status --porcelain      # must print nothing
node ssd-framework/onboarding/cli.mjs inspect --repo <consumer-repo>
```

It needs Node ≥ 22 and nothing else (Node builtins only, like the toolkit).
Every command that validates or writes checks the binding and **refuses** when:

- the CLI is not running from a git checkout (its commit is unknowable);
- the checkout has any uncommitted or untracked change (its templates are not the commit it claims);
- the checkout's `origin` is not `framework.repository`;
- `framework.ref` is not exactly the checkout's `HEAD`.

The reusable-workflow contracts the output is checked against — inputs,
secrets, and the permissions each called workflow statically requires — are read
from the immutable git object at that commit, never from `main`, `v1` or the
working tree. To move a consumer to a newer framework, check the CLI out at the
new SHA, set `framework.ref` to it, `render`, and review the diff. Design:
[onboarding-architecture.md § B.10](onboarding-architecture.md#b10-generator--framework-ref-binding-and-how-teams-obtain-the-cli).

## Commands

| Command | Writes | Purpose |
| --- | --- | --- |
| `inspect [--json]` | nothing | languages, manifests and their real coverage, Dockerfiles, existing workflows and scanner configs; with a config, the full report |
| `init` | `.ssd/onboarding.yml` | interactive: derives what it can prove, asks only owner decisions, shows the **effective Semgrep scope** before writing |
| `init --non-interactive --from <partial.yml\|.json>` | `.ssd/onboarding.yml` | automation: a partial config merged over derived defaults; refuses to default an owner decision |
| `validate [--json]` | nothing | config + repository + generated files; exit 1 on any blocking error **or drift** (CI-friendly) |
| `render` / `update` | generated files | regenerate from the config; refuses conflicts |
| `render --dry-run` | nothing | show every diff |
| `render --check` | nothing | exit 1 if any generated file differs from a fresh render, or a stale one exists |
| `render --adopt <path>` | that file | take ownership of an existing human-written file after reviewing its diff |
| `render --force <path>` | that file | overwrite a generated file that was edited by hand |
| `render --prune` | deletes | remove generated files the config no longer produces |
| `baseline status` | nothing | the rollout state and the next step |
| `baseline prepare [--run <id>]` | `.ssd/candidates/` | print the bootstrap dispatch command, or fetch and verify its candidate |
| `baseline accept` | baseline, config, workflow | accept the reviewed candidate (explicit confirmation) |
| `promote --enforce` | config, workflows | log-only → enforce (requires an accepted baseline) |

`--repo <dir>` points at the consumer repository (default: the current directory).
Nothing is ever committed; every change is a diff for a pull request.

## Configuration reference

Schema version `1`. The schema is **closed**: an unknown key is an error, so a
typo cannot silently leave a repository in log-only. All scalars except
`true`/`false` are strings (quote account IDs; the CLI does).

| Key | Default | Meaning |
| --- | --- | --- |
| `schemaVersion` | `'1'` | refused if anything else |
| `repository.slug` | from `origin` | `owner/name` |
| `repository.defaultBranch` | from `origin/HEAD` | PRs into it are scanned; **never guessed** — init refuses if it cannot be read |
| `framework.repository` | `IamRitz/ssd-security-framework` | |
| `framework.ref` | the CLI's own commit | an exact 40-character commit SHA, equal to the commit ssd-onboard runs from; tags and branches are refused |
| `profile` | — (required) | `source-only` \| `container-self-managed` \| `container-ecr-framework-gated` |
| `workflows.security` | `.github/workflows/security.yml` | any `.github/workflows/<name>.yml`; not `_`-prefixed |
| `workflows.delivery` | `.github/workflows/deploy.yml` | ECR profile only |
| `rollout.gateMode` | `log-only` | `enforce` only with `semgrep.baseline.state: accepted`; rendered as a **literal**, never a variable |
| `rollout.schedule` | `0 6 * * 1` | the weekly full sweep |
| `semgrep.rulesets` | `p/owasp-top-ten` + packs for detected languages | registry packs, `r/` rules, or local rule files |
| `semgrep.roots` | `['.']` | narrowing warns and lists what falls outside SAST |
| `semgrep.ignore.managed` | `true` | render `.semgrepignore`; `false` requires a committed one |
| `semgrep.ignore.patterns` | `[]` | gitignore-style; catch-alls refused; tests/migrations/IaC/scripts/config warn |
| `semgrep.baseline.path` | `security/baseline/semgrep-baseline.json` | |
| `semgrep.baseline.state` | `absent` | `absent` \| `accepted` — set by `baseline accept` |
| `semgrep.baseline.acceptedScope` | set by `baseline accept` | digest of rulesets + roots + ignores; a later change warns |
| `gitleaks.mode` | `default` | `default` (no file, `gitleaks_config: ''`) \| `managed` \| `existing` |
| `gitleaks.path` | `.gitleaks.toml` | managed/existing |
| `gitleaks.customRules[]` | `[]` | managed: `{id, description, regex, keywords?}` |
| `gitleaks.allowlists[]` | `[]` | managed: `{description, paths?, regexes?}`; broad entries refused |
| `trufflehog.excludePathsFile` | `''` | `''` = no exclusions; a path = newline-separated regexes |
| `container.dockerfile` / `.context` / `.imageName` | detected / `.` / repo name | container profiles |
| `delivery.aws.accountId` / `.region` | — | ECR profile |
| `delivery.ecr.repository` / `.ownership` | image name / `existing` | `managed` is Phase 2 |
| `delivery.oidcProvider` | `existing` | recorded for Phase 2 |
| `delivery.roles.pushScanRoleArn` / `deployRoleArn` | — | must differ; both in `accountId` |
| `delivery.roles.*Ownership` | `existing` | `managed` is Phase 2 (the ARN is still required to render) |
| `delivery.ssm.instanceId` / `.appPort` / `.containerName` | — / `3000` / image name | strict alphabets (they reach a root shell on the instance) |
| `delivery.environment` | `''` | a GitHub environment for the deploy job |
| `notifications.slack.enabled` | `false` | |
| `notifications.slack.githubSecretName` | `SECURITY_NOTIFY_SLACK_URL` | the **name** of the repository secret; the URL is never recorded |
| `breakGlass.mode` | `disabled` | only `disabled` is accepted: Phase 1 does not generate break-glass (below) |

**Never in this file:** AWS access keys, GitHub tokens, Slack tokens, signing
secrets, webhook URLs, private keys, URLs with credentials. Every string is
checked for those shapes when the file is read **and** before it is written.

## What gets generated

| Profile | Files | Capabilities |
| --- | --- | --- |
| `source-only` | security workflow, `.semgrepignore` | `library / none / none` |
| `container-self-managed` | + credential-free build and pre-push Trivy in the security workflow | `container / none / self-managed` |
| `container-ecr-framework-gated` | + the delivery workflow **once enforcing** | `container / ecr / framework-gated` |

Plus `.gitleaks.toml` when `gitleaks.mode: managed`. Every generated file starts
with three marker lines; the third carries `sha256(body)`, where the body is every
byte after the marker lines (the marker never covers itself). It is an
**overwrite/drift guard only** — not a signature or trust anchor; see
[the ownership rules](onboarding-architecture.md#b3-rendering).

The delivery workflow is generated only after `promote --enforce`: a log-only
delivery would push and deploy an image whose gates were not enforced, and its
gates hard-code `enforce` regardless.

## Coverage the report shows, and what blocks generation

`inspect` / `validate` answer: roots, ignored paths (with counts), in-scope
files, Gitleaks default-rule status, TruffleHog exclusions and what each matches,
every dependency manifest with its **real** coverage, and the container build.

Generation is **blocked** (exit 1, nothing written) by:

- a manifest the framework's scanners do not fully cover (below) — there is no override;
- a generator/framework-ref binding problem (§ Obtaining ssd-onboard), or a contract the pinned commit cannot satisfy;
- an existing `.gitleaks.toml` without `[extend] useDefault = true`, or with a broad allowlist;
- a TruffleHog exclude file with an invalid or catch-all pattern;
- an owner-managed Semgrep scope with no `.semgrepignore`, a Semgrep root that does not exist, or a scope with no source files;
- an inconsistent baseline state;
- an input or secret the pinned framework ref does not declare;
- a conflicting file (hand-edited generated file, or human-owned file).

### Dependency layouts

| Class | Example | |
| --- | --- | --- |
| `native+osv` | root `package-lock.json`, root `requirements.txt` | covered |
| `osv` | `go.mod`, `Cargo.lock`, `Gemfile.lock` | covered (no native scanner exists) |
| `workspace` / `covered-by-lockfile` / `no-dependencies` | npm workspace member; `pyproject.toml` + `uv.lock` | covered |
| `osv-unverified` | `pnpm-lock.yaml`, `composer.lock` | warning: OSV documents it; not verified against the pinned image |
| `osv-only` | `services/api/package-lock.json`, root `yarn.lock` / `pnpm-lock.yaml` / `poetry.lock` | **blocks** |
| `uncovered` | `package.json` with deps and no lockfile, `pyproject.toml` with deps and no lockfile, `setup.py`, `requirements/base.txt` | **blocks** |

There is **no local acknowledgement**: a gap accepted in this file would expire
only when someone next ran ssd-onboard, while CI kept passing. A future version
may add a conformance-backed, CI-enforced exception (owner, reason, expiry,
control ID); see [architecture § B.6](onboarding-architecture.md#b6-dependency-coverage-contract-option-b-strict).

**Currently unsupported layouts** (blocked by default): monorepos whose npm or
Python projects live below the root, root `yarn.lock` / `pnpm-lock.yaml` /
`poetry.lock` / `Pipfile.lock` / `uv.lock` projects (OSV-Scanner only), and any
Python project declared only in `pyproject.toml` / `setup.py` / `setup.cfg` /
`Pipfile` without a lockfile. The fix for the first group is a framework
change (architecture doc C.3); for the last, commit a lockfile.

## The rollout, end to end

```
init                      gate log-only, scope '.', baseline absent
render                    PR: security workflow with a bootstrap dispatch checkbox
                          (merge it)
baseline prepare          prints: gh workflow run security.yml -f bootstrap_baseline=true
                          (dispatch it — a FULL scan; a PR run is refused)
baseline prepare --run N  verifies the run (workflow_dispatch on the default branch,
                          DO-NOT-BASELINE, integrity, bootstrap) and the candidate's
                          provenance record (digest, bytes, run, commit, config),
                          then installs a CANDIDATE only
                          (review .ssd/candidates/semgrep-baseline.candidate.json)
git checkout -b accept-baseline <scanned-sha>
                          accept only from EXACTLY the scanned commit, clean tree
baseline accept           re-checks provenance against this checkout (HEAD, origin,
                          Semgrep configs/paths, .semgrepignore hash, framework ref),
                          THEN shows every finding and asks you to type the count;
                          writes the baseline, sets state: accepted, removes the
                          bootstrap input (PR; watch a few PRs in log-only)
promote --enforce         refuses without a valid accepted baseline; shows the diff;
                          generates the delivery workflow for the ECR profile
                          (PR; require `security-gate` in branch protection)
```

Nothing silently switches modes, accepts findings, regenerates a baseline, or
suppresses a finding to make onboarding green. A baseline that already exists is
never overwritten; rebuilding one means deleting it in a reviewed pull request.

## Break-glass

Not generated by Phase 1. Emitting `break_glass_enabled: true` would need
conformance evidence that the approval channel works, and none exists yet (the
shipped examples hard-code a PASS, which is a known gap). `breakGlass.mode`
accepts only `disabled`; generated callers pass `break_glass_enabled: false`, and
conformance reports the control N/A with that reason. Phase 3 reintroduces it
with observed evidence
([architecture § B.8](onboarding-architecture.md#b8-break-glass-is-not-generated-choice-b)).

## OIDC: generated callers hold no token

Generated source callers use **`_source-scan.yml`**, the OIDC-free source
workflow — no job in it can request a GitHub OIDC token — so `ssd-onboard`
renders exactly:

```yaml
  source-security:
    uses: <framework>/.github/workflows/_source-scan.yml@<ref>
    permissions:
      contents: read
      pull-requests: write
```

Earlier versions granted `id-token: write` here and flagged it as an
`UNRESOLVED FRAMEWORK LIMITATION`, because the only source workflow at the time
(`_source-security.yml`) declared the token on its `source-gate` job and GitHub
validates reusable-workflow permissions statically. That is resolved
([architecture § B.9](onboarding-architecture.md#b9-resolved-oidc-least-privilege-for-callers-without-break-glass)).

When Lambda break-glass **is** used, OIDC belongs to a separate `break-glass`
job calling `_break-glass-lambda.yml`, never to the scanning caller.
`ssd-onboard` does not generate that job — `breakGlass.mode` accepts only
`disabled` (see *Break-glass* above), so a generated caller has no `id-token`
grant anywhere in its source path. Wire it by hand from
`examples/container-ecr/security.yml` if you need it.

The legacy `_source-security.yml` stays OIDC-capable for **existing v1 callers**
whose in-job Lambda break-glass path is a published v1 contract. If you point a
caller at it, the contract check still reports the grant as an unresolved
limitation — that warning is now specific to that legacy path.

## Migration

### From a hand-copied example

1. `ssd-onboard init`, answering to match the current workflow.
2. `ssd-onboard render --dry-run` and read the diff against your file.
3. `ssd-onboard render --adopt .github/workflows/security.yml`.

Expect these deliberate differences: the gate mode becomes a literal; Semgrep
scans `.` with an explicit `.semgrepignore` (tests become in scope — new findings
may appear); `gitleaks_config` / `trufflehog_exclude_paths` become explicit; the
Slack webhook moves to a secret; `BOOTSTRAP_BASELINE` becomes a dispatch
checkbox; a `gate-mode` visibility check appears.

### Existing Gitleaks configurations

A `.gitleaks.toml` without `[extend] useDefault = true` replaces every built-in
rule (re-verified by `tools/verify-scanner-behaviour.mjs`). `ssd-onboard`
refuses such a file in `existing` mode. Review it: either add the `[extend]`
table, or move its consumer-specific rules into `gitleaks.customRules` and let
ssd-onboard manage the file. Do not add broad allowlists to make the scan quiet.

### Slack: from a repository variable to a secret

The URL in `vars.SECURITY_NOTIFY_SLACK_URL` is a credential that was being
printed in run logs. Rotate it (create a new webhook, delete the old one — the old
URL has been visible), then:

```sh
gh secret set SECURITY_NOTIFY_SLACK_URL --repo <owner>/<repo>   # prompts; value never on argv
gh variable delete SECURITY_NOTIFY_SLACK_URL --repo <owner>/<repo>
```

and pass it as `secrets: slack_notify_webhook: ${{ secrets.SECURITY_NOTIFY_SLACK_URL }}`
(`ssd-onboard render` does this when `notifications.slack.enabled: true`). The
old `slack_notify_url` input still works within v1 but warns on every run.

### CODEOWNERS

`.ssd/onboarding.yml` now decides the gate mode and every scan's scope, so it
needs the same review as the workflows. Cover `/.ssd/`, `/.github/workflows/`,
the baseline, `.semgrepignore`, and any Gitleaks/TruffleHog config
([example](../examples/CODEOWNERS.example)); `validate` warns about gaps.
