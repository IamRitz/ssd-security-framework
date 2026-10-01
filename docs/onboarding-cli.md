# `ssd-onboard`: configuration-driven onboarding

`ssd-onboard` generates and maintains a consumer repository's security (and,
for framework-gated delivery, deployment) workflows from one reviewed,
**non-secret** file: `.ssd/onboarding.yml`. It replaces copying an example and
hand-editing YAML.

Design record and gap analysis: [onboarding-architecture.md](onboarding-architecture.md).
The manual procedure it automates: [onboarding.md](onboarding.md).

> **Phase 1 boundary.** The repository commands edit files in the consumer
> repository and nothing else. They make **no AWS calls** and **no GitHub
> mutations**: they run `git` read-only and, for `baseline prepare --run`,
> `gh api` (GET) and `gh run download` behind an allowlist.
>
> **Phase 2 boundary.** `aws doctor` is a separate, **read-only** command that
> talks to AWS with the operator's own AWS CLI credentials
> ([§ AWS readiness](#aws-readiness-aws-doctor-phase-2a)). It writes no
> repository file and makes no GitHub call. `aws plan|apply|verify` and the
> `github` commands are designed (architecture doc, Parts D–E) but not
> implemented, and exit 2.

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

## First-time onboarding: `onboard`

The recommended first step is one guided command:

```sh
node ssd-framework/onboarding/cli.mjs onboard --repo <consumer-repo>
```

`onboard` runs `init`'s interview (or reads `--non-interactive --from
<partial.yml|.json>`, exactly as `init` does), then shows the complete plan: the
effective coverage, the security model, and every file it would create, with a
diff for any file it would adopt or overwrite. Only after an explicit **yes**
(the default is no) does it write `.ssd/onboarding.yml` and the generated files,
then re-reads the repository and requires `validate` and `render --check` to
pass, and shows the `doctor` readiness report.

**One command is not one step to production.** `onboard` creates the initial,
reviewable integration state and nothing more:

- it does **not** accept a Semgrep baseline (the state stays `absent`);
- it does **not** enable enforcement (the gate stays `log-only`);
- it does **not** configure GitHub branch protection, rulesets or CODEOWNERS,
  contact AWS, commit, push, or open a pull request.

A fresh repository therefore ends in the `onboarding` rollout state, where
doctor reports WARN (baseline, gate mode) and NOT VERIFIED (GitHub governance)
by design. The rest of the rollout (below) stays explicit, one reviewed step at
a time.

`onboard` is **stricter than `init`** about writing: if anything would block
generation (a missing owner decision, a schema error, an unbound or dirty
framework checkout, a repository identity that is not the origin, an
unsupported dependency layout, a conflicting file) it writes **nothing**. Every
target path is proven confined before the first write. An existing
human-written or hand-edited file is a CONFLICT unless you name exactly that
path with `--adopt <path>` or `--force <path>`; nothing is adopted or forced
automatically. If `.ssd/onboarding.yml` already exists, `onboard` exits 1 and
points to `validate`, `doctor` and `render`; reinitializing is the deliberate
`init --overwrite`. The profile is always an explicit choice: a Dockerfile is
not taken as proof that the repository ships an image.

If a write fails part-way (a genuine I/O error), `onboard` exits 1, lists
exactly the files it wrote and the one that failed, and rolls nothing back;
once the cause is fixed, `ssd-onboard render` completes the generated files.

Exit codes: `0` onboarding written and validated (WARN / NOT VERIFIED allowed),
`1` refused, declined or failed, `2` command-line usage error.

## Commands

The low-level commands below remain the building blocks `onboard` composes, and
the tools for everything after first onboarding.

| Command | Writes | Purpose |
| --- | --- | --- |
| `onboard [--non-interactive --from <file>] [--adopt <path>]… [--force <path>]…` | config + generated files | **recommended first step**: init + render + validate + doctor, writing only a state that validates, after confirmation (above) |
| `inspect [--json]` | nothing | languages, manifests and their real coverage, Dockerfiles, existing workflows and scanner configs; with a config, the full report |
| `init` | `.ssd/onboarding.yml` | interactive: derives what it can prove, asks only owner decisions, shows the **effective Semgrep scope** before writing |
| `init --non-interactive --from <partial.yml\|.json>` | `.ssd/onboarding.yml` | automation: a partial config merged over derived defaults; refuses to default an owner decision |
| `validate [--json]` | nothing | config + repository + generated files; exit 1 on any blocking error **or drift** (CI-friendly) |
| `doctor [--json]` | nothing | operational readiness: lifecycle stage, drift, governance gaps; exit 1 on any FAIL (§ Readiness: doctor) |
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
| `aws doctor [--region <r>] [--json]` | nothing (no AWS change either) | Phase 2A: read-only AWS readiness of the configured delivery (§ AWS readiness) |

`--repo <dir>` points at the consumer repository (default: the current directory).
Nothing is ever committed; every change is a diff for a pull request.

### Output

Human-readable output is presentation only: its layout may change between
versions, and nothing should parse it. Scripts use `--json` (`inspect`,
`validate`, `doctor`, `aws doctor`) and the exit code.

- **Color** is used only when the stream is an interactive terminal. Redirected
  or piped output, CI logs and `--json` are plain text. Color is also off when
  `NO_COLOR` is set to any non-empty value ([no-color.org](https://no-color.org))
  or `TERM=dumb`. There is no flag to force it on.
- **Status is never color alone.** Every status carries its symbol and word:
  `✓ PASS`, `! WARN`, `✗ FAIL`, `? NOT VERIFIED`. Report results are `READY`,
  `READY WITH WARNINGS` or `BLOCKED`; doctor results are its JSON `outcome`,
  verbatim. Planned files are marked `+ create`, `~ update`, `= unchanged`,
  `! conflict`, `! overwrite`, `~ adopt`, `- stale`.
- **Nothing is truncated.** Paths, SHAs, commands and messages are printed in
  full; a value too long to align moves to its own line.
- **Repository-controlled text cannot drive the terminal.** File names, config
  values, scanner messages and diffs are shown with terminal control characters
  made visible (`\x1b[31m`, `\r`, `\u202e`) rather than executed or silently
  dropped, so an ANSI, OSC (title, hyperlink) or carriage-return injection
  attempt is visible in the output. `--json` output is byte-compatible with the
  previous behavior: `JSON.stringify` escapes C0 controls such as ESC and CR,
  while other Unicode/control characters remain JSON data and are not passed
  through the human-output sanitizer.
- **Streams are unchanged**: reports on stdout; refusals, errors and prompts on
  stderr. With `--json`, stdout holds exactly one JSON document.

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
| `delivery.ecr.repository` / `.ownership` | image name / `existing` | `managed` is Phase 2; `aws doctor` reports actual ownership |
| `delivery.oidcProvider` | `existing` | ownership mode of the shared GitHub OIDC provider; `aws doctor` reports actual ownership |
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
| `native+osv` | `package-lock.json` / `npm-shrinkwrap.json` of any npm project, root or nested (`frontend/package-lock.json`); root `requirements.txt` | covered |
| `osv` | `go.mod`, `Cargo.lock`, `Gemfile.lock` | covered (no native scanner exists) |
| `workspace` / `covered-by-lockfile` / `no-dependencies` | npm workspace member; `pyproject.toml` + `uv.lock` | covered |
| `osv-unverified` | `pnpm-lock.yaml`, `composer.lock` | warning: OSV documents it; not verified against the pinned image |
| `osv-only` | `services/py/requirements.txt`, root `yarn.lock` / `pnpm-lock.yaml` / `poetry.lock` | **blocks** |
| `osv-skipped` | a committed `Cargo.lock` / `poetry.lock` / `yarn.lock` / … that `.gitignore` also lists (the recursive OSV-Scanner walk skips it); npm dependency-root lockfiles are exempt, OSV-Scanner reads those by name | **blocks** — remove the ignore rule |
| `uncovered` | `package.json` with deps and no lockfile, `pyproject.toml` with deps and no lockfile, `setup.py`, `requirements/base.txt`, any lockfile that is not tracked by git | **blocks** |

**Nested npm projects are supported.** Every directory with a tracked
`package-lock.json` or `npm-shrinkwrap.json` is an npm dependency root; CI runs
`npm audit --package-lock-only` separately in each (pinned with `--prefix`),
and OSV-Scanner scans each of those lockfiles by name — even one `.gitignore`
lists, as long as it is tracked. Nothing needs to be configured. A finding from
a nested root names its lockfile and is reproduced with
`npm audit --package-lock-only --prefix <root>`; a project `.npmrc` in a root is
honoured by npm, as it always was at the repository root.
Commit the lockfiles: an ignored or untracked lockfile is not in the CI checkout
and gives no coverage. See [architecture § C.3](onboarding-architecture.md#c3-npm-dependency-roots-implemented).

There is **no local acknowledgement**: a gap accepted in this file would expire
only when someone next ran ssd-onboard, while CI kept passing. A future version
may add a conformance-backed, CI-enforced exception (owner, reason, expiry,
control ID); see [architecture § B.6](onboarding-architecture.md#b6-dependency-coverage-contract-option-b-strict).

**Currently unsupported layouts** (blocked by default): Python projects below
the root (pip-audit reads the root `requirements.txt` only), root `yarn.lock` /
`pnpm-lock.yaml` / `poetry.lock` / `Pipfile.lock` / `uv.lock` projects
(OSV-Scanner only), and any Python project declared only in `pyproject.toml` /
`setup.py` / `setup.cfg` / `Pipfile` without a lockfile. The first two need
framework changes that do not exist yet; for the last, commit a lockfile.

## Readiness: doctor

`validate` answers *is the configuration valid?*; `doctor` answers *is this
repository operationally ready to use the framework safely?* It is a read-only
view of the **same** analysis `validate` and `render --check` decide from —
it re-implements none of it — reported as one check per concern:

| Check | FAIL when | Otherwise |
| --- | --- | --- |
| Configuration | the config does not validate (then no other check is claimed) | WARN for config warnings |
| Repository identity | origin or origin/HEAD contradicts the config | WARN: identity not established (non-git, no GitHub origin, no origin/HEAD) |
| Framework pin | the CLI checkout is not a clean checkout of `framework.repository` at `framework.ref` | |
| Workflow contract | a generated call disagrees with the pinned reusable workflow | NOT VERIFIED while the pin fails |
| Generated workflow | `render --check` would fail (drift, conflict, stale file) | |
| Semgrep baseline | the lifecycle is inconsistent (e.g. `accepted` with no file) | WARN while onboarding (`absent`, a valid state) |
| Gate mode | | WARN in `log-only` |
| Bootstrap wiring | | NOT VERIFIED while the workflow is not the verified render |
| Source workflow OIDC boundary | the pinned contract rejects a `source-security` job, or a drifted workflow grants `id-token: write` / passes `secrets: inherit` there | NOT VERIFIED while unproven |
| Semgrep / secret scanning / dependency coverage / container | the corresponding `validate` errors | WARN for its warnings |
| CODEOWNERS coverage | | WARN on a missing file or path; otherwise **NOT VERIFIED** |
| GitHub merge governance | | always **NOT VERIFIED** |
| AWS delivery prerequisites (ECR profile), Slack secret (if enabled) | | always **NOT VERIFIED** (for AWS, run `aws doctor`) |

Every `validate` error appears as a FAIL of some check (an unknown one in
"Other validation problems"), and doctor adds no FAIL of its own. **NOT
VERIFIED** means *cannot be proven from this checkout*, not *passed*: doctor
makes no GitHub or AWS calls, and a job named `security-gate` in a workflow
says nothing about whether the default branch **requires** it. The CODEOWNERS
matcher is a conservative local heuristic (last matching rule wins, an
ownerless rule removes ownership, `/*` is top-level only, and a pattern it
cannot evaluate counts as not covered); it cannot see whether GitHub requires
code-owner review, so doctor never reports that coverage as PASS.

Exit codes: `0` no FAIL (WARN and NOT VERIFIED do not fail — they are normal
during rollout); `1` one or more FAILs, or a config/repository state that
prevents a diagnosis (missing or malformed config), as for every other
command; `2` a command-line usage error.

With `--json`, a diagnosis that cannot be built (exit 1) is still one JSON
document: `{"schemaVersion": 1, "command": "doctor", "outcome": "ERROR",
"error": {"kind": "config-missing" | "config-malformed" | "runtime",
"message": …}}`. Usage errors are rejected by the shared argument parser
before doctor runs, so they stay plain text on stderr (exit 2).

Remediation links to GitHub settings are shown only when origin is exactly
`github.com` and names `repository.slug`; for any other host (GitHub
Enterprise included) doctor gives the host-neutral steps (*repository
settings → Rules → Rulesets*) without a link.

## AWS readiness: `aws doctor` (Phase 2A)

`doctor` never contacts AWS. `aws doctor` is the separately authenticated,
**read-only** check of the AWS side of a `container-ecr-framework-gated`
delivery. It reads `.ssd/onboarding.yml` (`delivery.*`, `repository.*`) and
nothing else from the repository, writes nothing, and makes no GitHub call.

```sh
AWS_PROFILE=<operator-profile> node ssd-framework/onboarding/cli.mjs aws doctor --repo <consumer-repo>
```

**Credentials** come only from the AWS CLI's provider chain (profile, SSO,
role credentials…). There is no option that takes a key; error text is reduced
to the AWS error code and message with credential-shaped values redacted, and a
credential failure prints no provider output at all.

**Region**: `--region` if given, else `delivery.aws.region` — never the AWS
CLI's default. A `--region` that differs from `delivery.aws.region` blocks
before AWS is contacted.

**Order**: `sts get-caller-identity` first. A caller in another account, or the
account **root** user, blocks before any resource is read.

**Read-only by construction**: every call goes through one wrapper
(`execFile`, argv array, no shell) whose allowlist names each permitted
`service operation` and its permitted parameters explicitly; anything else —
every mutating verb, an unlisted read, `--endpoint-url`, `--profile`,
`--debug`, `--cli-input-json`, and any parameter **value** beginning with
`file://`, `fileb://`, `http://` or `https://` (which the AWS CLI would resolve
by reading a local file or a URL) — is refused before it runs. There is no mutating
wrapper in this version.

| Section | Check | FAIL when | NOT VERIFIED when |
| --- | --- | --- | --- |
| Identity | Caller account / principal / region | wrong account; root user; `--region` ≠ config | |
| GitHub OIDC | Provider | absent; another account; audience list lacks `sts.amazonaws.com` (WARN: extra audiences) | the provider cannot be read |
| | Subject format | | **always** (not required): legacy vs immutable customization needs the GitHub API |
| ECR | Repository | absent; public repository policy | cannot be read |
| | Tag immutability | | (WARN when MUTABLE: deploys pin digests, but a tag can be repointed) |
| | Registry scanning coverage | no rule scans the repository automatically (MANUAL is not coverage) | the configuration cannot be read, the scan type is missing or not BASIC/ENHANCED, or an unevaluated rule could matter |
| | Inspector (only with ENHANCED) | Inspector ECR scanning not ENABLED; repository coverage INACTIVE | account status cannot be read |
| IAM | Push/scan and deploy role | absent; same name at another path | cannot be read |
| | … trust | any trust path beyond this repository + the role's context: wildcard or missing `sub`, org-wide, other repo/branch/environment, `pull_request`, wrong/missing audience, wrong provider, `*` or cross-account principal, unsupported operator (WARN: exact `StringLike`, immutable-format IDs unverified, narrowing extra conditions) | the role is unavailable |
| | … permissions | a needed action not granted, or granted but denied by simulation; a forbidden one granted **or possibly granted** — conditionally, through `NotAction`/`NotResource`, or despite a conditional Deny (push role reaching SSM, deploy role writing ECR, other repository/instance, `iam:PassRole`); `*:*`, or `Allow` + `NotAction` on every resource (possible administrator) | a policy cannot be read; a needed action is granted only conditionally or through `NotAction`/`NotResource`; with an unknown scan type, the Inspector statement is missing |
| SSM | Instance | absent; another account; not running | cannot be read |
| | Managed instance Online | not managed by SSM; PingStatus ≠ Online | cannot be read |
| | Instance role (ECR pull) | no profile; profile in another account or without exactly one role; no ECR login/pull on the repository (a **proposed** policy is printed, never attached) | cannot be read |
| Ownership | per resource | configured `managed`, but the resource exists and is not owned | the stack lookup is denied |

Role contexts: push+scan trusts only `ref:refs/heads/<repository.defaultBranch>`;
deploy trusts only `environment:<delivery.environment>` (with no environment it
trusts the default branch, and WARNs that no reviewer can gate it). Trust and
permission results are **policy-document analysis**; where the operator may call
`iam simulate-principal-policy`, simulation is consulted too and the basis says
so. Neither is runtime proof: SCPs, resource policies, session policies and VPC
endpoint policies can still deny.

**Access denied is never absence.** Only the not-found code AWS returns for
that specific call makes a resource `absent`; a denial, throttle, timeout or
malformed response is NOT VERIFIED.

**Ownership: existence is not ownership.** ssd-onboard's stacks have derived
names (never configured):

| Scope | Stack name |
| --- | --- |
| per repository | `ssd-delivery-<owner>-<repo>-<h8>` — lower-cased, other characters → `-`; `<h8>` = first 8 hex of sha256(`github.com/<owner>/<repo>` lower-cased), so `acme/my.app` and `acme/my-app` differ while `Acme/App` and `acme/app` (one GitHub repository) agree |
| shared: GitHub OIDC provider | `ssd-shared-github-oidc` |
| shared: ECR registry scanning | `ssd-shared-ecr-scanning` |

The name only **locates** the owner; it is not proof. A resource is reported
`managed` only if CloudFormation, in `delivery.aws.region`, lists it as a
physical resource of the expected type of **exactly that stack**, the stack is
in a settled, successful state (`CREATE_COMPLETE`, `UPDATE_COMPLETE`,
`UPDATE_ROLLBACK_COMPLETE`, `IMPORT_COMPLETE`, `IMPORT_ROLLBACK_COMPLETE`), and
its tags are `ssd:framework=ssd-security-framework`, `ssd:managed-by=ssd-onboard`,
`ssd:environment=production` and (per repository)
`ssd:consumer-repository=<owner>/<repo>` lower-cased. A correctly tagged
ssd-onboard stack with any other name is not the owner. Anything else that exists
is `exists, not owned` — expected for `existing`, a **FAIL** for `managed` (it
will never be adopted by name). A resource owned by an ssd-onboard stack but
configured `existing` is a WARN.

Outcomes and exit codes. Every check carries `required` (in JSON); the human
output appends **(advisory)** to a non-PASS check whose `required` is false, and
the result line splits NOT VERIFIED into required and advisory:

| Condition | Outcome | Exit |
| --- | --- | --- |
| any FAIL | `BLOCKED` | 1 |
| a **required** check is NOT VERIFIED | `NOT VERIFIED` | 1 |
| only WARN and/or **advisory** NOT VERIFIED | `READY WITH WARNINGS` | 0 |
| everything PASS | `READY` | 0 |
| cannot start (no config, non-ECR profile, no AWS CLI, no credentials, timeout) | `ERROR` | 1 |
| usage error | — | 2 |

Advisory checks are exactly: *Subject format* (cannot be proven from AWS),
*Tag immutability* (informational; the repository itself is required), and
*Ownership* of a resource configured `existing`. Ownership of a `managed`
resource, and every other check — identity, OIDC provider, ECR repository,
scanning coverage, Inspector, roles, trust, permissions, SSM — is required, so
an access denial on any of them exits 1.

```
GitHub OIDC
  ✓ PASS          Provider
  ? NOT VERIFIED  Subject format (advisory)
…
Result
  ! READY WITH WARNINGS  0 FAIL · 0 WARN · 1 NOT VERIFIED (0 required, 1 advisory) · 20 PASS
```

`--json` prints one document:

```json
{
  "schemaVersion": 1,
  "command": "aws doctor",
  "target": { "repository": "acme/app", "account": "012345678901", "region": "us-east-1", "regionSource": "config",
              "caller": { "account": "012345678901", "arn": "arn:aws:sts::012345678901:assumed-role/ops/alice", "userId": "…", "kind": "assumed-role", "partition": "aws" } },
  "outcome": "READY_WITH_WARNINGS",
  "counts": { "PASS": 20, "WARN": 0, "FAIL": 0, "NOT VERIFIED": 1 },
  "checks": [ { "id": "identity.account", "section": "Identity", "title": "Caller account", "status": "PASS", "required": true,
                "basis": "runtime", "observed": ["…"], "expected": ["…"], "findings": [], "remediation": [] } ],
  "skipped": null,
  "awsCalls": ["sts get-caller-identity", "iam list-open-id-connect-providers", "…"]
}
```

or, when it cannot run, `{"schemaVersion": 1, "command": "aws doctor",
"target": …, "outcome": "ERROR", "error": {"kind": "configuration" |
"command-unavailable" | "authentication" | "timeout" | "malformed-json" | …,
"code": …, "message": …}}`.

The operator needs read access only: `sts:GetCallerIdentity`,
`iam:List/GetOpenIDConnectProvider(s)`, `iam:GetRole`, `iam:List/GetRolePolicy`,
`iam:ListAttachedRolePolicies`, `iam:GetPolicy(Version)`,
`iam:GetInstanceProfile`, optionally `iam:SimulatePrincipalPolicy`,
`ecr:DescribeRepositories`, `ecr:GetLifecyclePolicy`, `ecr:GetRepositoryPolicy`,
`ecr:ListTagsForResource`, `ecr:GetRegistryScanningConfiguration`,
`inspector2:BatchGetAccountStatus`, `inspector2:ListCoverage`,
`ssm:DescribeInstanceInformation`, `ec2:DescribeInstances`,
`cloudformation:DescribeStackResources`, `cloudformation:DescribeStacks`. A
missing one makes the affected check NOT VERIFIED, never FAIL-as-absent.

## The rollout, end to end

```
onboard                   (= init + render + validate + doctor)
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
