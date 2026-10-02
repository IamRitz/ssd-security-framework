# Consumer onboarding: architecture and gap analysis

This document is the design record for `ssd-onboard`, the configuration-driven
onboarding CLI. It was written from the repository as it stood at
`70421b4` (branch `fix/evidence-backed-feedback`, which contains the requested
reference `0683037`), and every claim about scanner behaviour below was
**verified against the pinned scanner images**, not recalled.

- [Part A](#part-a--what-the-current-framework-actually-does) — what the current framework does, with evidence
- [Part B](#part-b--architecture) — the architecture chosen
- [Part C](#part-c--reusable-workflow-api-changes) — reusable-workflow API changes
- [Part D](#part-d--phase-2-aws-doctor--plan--apply--verify) — Phase 2 design (AWS)
- [Part E](#part-e--phase-3-break-glass-provisioning) — Phase 3 design (break-glass)

Usage is in [onboarding-cli.md](onboarding-cli.md).

---

## Part A — What the current framework actually does

### A.1 Gitleaks: a custom config silently REPLACES the default ruleset

Pinned image `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0…` reports `v8.30.1`.
A throwaway repository containing one AWS access key and one GitHub PAT was
scanned three ways:

| Config | Findings | Rules that fired |
| --- | --- | --- |
| none (default ruleset) | 2 | `aws-access-token`, `github-pat` |
| custom `[[rules]]` only | **0** | — |
| custom `[[rules]]` + `[extend] useDefault = true` | 2 | `aws-access-token`, `github-pat` |

A `.gitleaks.toml` that only adds a rule turns off every built-in rule. The
live scratch consumer (`IamRitz/ssd-scratch-consumer`) ships exactly that file,
so its secret scan currently detects only its one synthetic pattern. The
reusable workflow's wording ("absent means the scanner's default ruleset") is
true but incomplete: **present-without-extend means no default ruleset**.

### A.2 Semgrep: no `.semgrepignore` means tests are NOT scanned

Pinned image `semgrep/semgrep@sha256:12672acd…` reports `1.176.0`. The same
`eval(user_input)` line was placed in `src/`, `tests/`, `test/`, `build/`,
`vendor/`, `node_modules/x/`, `migrations/` and `src/foo_test.py`:

| `.semgrepignore` | Paths reported |
| --- | --- |
| absent | `migrations/`, `src/a.py`, `src/foo_test.py` — **tests/, test/, build/, vendor/, node_modules/ skipped** |
| present, empty | all eight |
| `build/ node_modules/ vendor/` | everything except those three |

The framework's default `semgrep_paths: .` therefore does **not** mean "the
whole repository": with no `.semgrepignore`, Semgrep applies its built-in
ignore list and test code is outside SAST coverage without anything saying so.
A consumer `.semgrepignore` replaces that built-in list entirely. Every shipped
example also narrowed to `semgrep_paths: src`.

A fuller matrix (recorded in `test/fixtures/scanner-behaviour/semgrep-scope.json`
and re-verified by `tools/verify-scanner-behaviour.mjs`, which also renders the
real generated file) adds: `migrations/`, `scripts/`, `infra/`, `config/`,
`generated/` and `__generated__/` are scanned in every case; the comments-only
`.semgrepignore` ssd-onboard generates with no exclusions scans exactly what an
empty file scans; a generated file with two confirmed patterns excludes exactly
those two; and `.gitignore` removes only **untracked** files — a tracked file
matching `.gitignore` is still scanned, and a CI checkout contains only tracked
files, so `.gitignore` does not change CI scope.

### A.3 Dependency scanning: what is and is not covered

Pinned OSV-Scanner `ghcr.io/google/osv-scanner@sha256:5116601d…` (v2.4.0), run
exactly as the workflow runs it (`scan source --recursive --allow-no-lockfiles`).
That recursive walk skips every path `.gitignore` lists **even when it is
tracked** (verified), so a force-added, gitignored lockfile — OWASP Juice Shop's
layout — is not read by it. npm dependency-root lockfiles are therefore also
scanned by a second, explicit run that names each one (C.3,
`tools/verify-scanner-behaviour.mjs` § 3):

| File | OSV-Scanner | Language-native (as wired today) |
| --- | --- | --- |
| `package-lock.json` / `npm-shrinkwrap.json` at root | scanned | `npm audit --package-lock-only --prefix .` |
| `package-lock.json` / `npm-shrinkwrap.json` nested (`svc/api/`) | scanned | `npm audit --package-lock-only --prefix svc/api` — one run per npm dependency root |
| npm root lockfile that `.gitignore` lists (tracked) | **skipped by the recursive walk**; scanned by the explicit npm-root run | as for its location |
| any other tracked lockfile that `.gitignore` lists | **not scanned** — classified `osv-skipped`, which blocks (B.6) | as for its location |
| `requirements.txt` at root | scanned | `pip-audit -r requirements.txt` |
| `requirements.txt` nested | **scanned** | **not run** |
| `requirements-dev.txt` | scanned | not run |
| `requirements/base.txt` | **not scanned** | not run |
| `pyproject.toml` (PEP 621, no lockfile) | **not scanned** | not run |
| `setup.py` | **not scanned** | not run |
| `package.json` with dependencies, no lockfile | **not scanned** | not run |
| `poetry.lock`, `Pipfile.lock`, `uv.lock`, `yarn.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock` | scanned | none exists |

npm audit runs once per **npm dependency root**: every directory holding a
tracked `package-lock.json` or `npm-shrinkwrap.json` outside `node_modules/`
(`security/scripts/dependency-roots.mjs`; see C.3). `--prefix` is not cosmetic:
without it npm walks up from the working directory and, for a lockfile with no
sibling `package.json` or for an npm workspace member, silently audits the
ancestor project instead (verified with npm 10). The pinned OSV-Scanner reads
nested `package-lock.json` and `npm-shrinkwrap.json` files and reports each
under its own `source.path` (verified against the pinned digest).

The pip-audit step still hard-codes `--requirement requirements.txt` at the
root, so nested Python projects remain OSV-only. OSV-Scanner is a genuine recursive
backstop for lockfiles, but **a manifest with no lockfile is scanned by nothing**,
and the `dependency_scan_result: success` output does not distinguish "every
manifest scanned" from "no manifest understood".

### A.4 Baseline bootstrap from a pull request produces an incomplete baseline

`_source-security.yml` runs Semgrep with `--baseline-commit=<merge-base>` on
`pull_request` and `--baseline-commit=<before>` on `push`, so those scans report
only findings the change introduced. `docs/onboarding.md §1.1` said "open a PR,
or dispatch it". A bootstrap run on a PR therefore generates a candidate
baseline that omits the repository's existing backlog; the next full scan (the
weekly schedule) would then BLOCK on everything the baseline was meant to
accept. Only `schedule` and `workflow_dispatch` perform a full-tree scan.

### A.5 The Slack webhook is a secret passed as an input

`slack_notify_url` is a `string` input, fed from `vars.SECURITY_NOTIFY_SLACK_URL`
in every example. An incoming-webhook URL **is** the credential: anyone holding it
can post to the channel. Repository variables are not masked, and GitHub prints a
step's `env:` block in the run log, so the URL appears in every notifier step log
readable by anyone with read access to Actions. It also cannot be rotated
without editing every caller that hard-codes it.

The notifier step is the only consumer: the value reaches no scanner job today,
so the smallest safe fix is a declared, optional reusable-workflow **secret**
referenced only by the notifier step (Part C).

### A.6 Other gaps found

| Gap | Where | Consequence |
| --- | --- | --- |
| `source-only` and `python-self-managed` examples grant `source-security` no `id-token: write`, but `_source-security.yml`'s `source-gate` job requests it | examples | the caller fails to start; the live scratch consumer needed commit `b1738f6` ("grant OIDC token permission to source security"). **Resolved in v1.2.0 (B.9):** those examples now call the OIDC-free `_source-scan.yml` and grant no token at all |
| `gate_mode: ${{ vars.GATE_MODE \|\| … }}` | every example | the gate can be switched to log-only by changing a repository variable, with no pull request and no CODEOWNERS review |
| `gitleaks_config` / `trufflehog_exclude_paths` default to a file name that is used **if it exists** | `_source-security.yml` | a stray `.trufflehog-exclude-paths.txt` added in any PR narrows the secret scan without touching a workflow |
| the `gate-mode` visibility check is documented but not shipped | `docs/onboarding.md §1.5`, `workflow-contracts.md` vs `examples/` | reviewers are told to expect a check that never appears |
| `"break-glass":{"status":"pass"}` is hard-coded | container examples | conformance records a configured approval channel as proven |
| `ssm-deploy.mjs` defaults `--container-name secure-software-delivery` and maps `-p <port>:3000` | deploy example | every consumer's container shares the POC's name, and the app must listen on 3000 |
| `container_name` / `app_port` are interpolated into a root shell on the instance | `ssm-deploy.mjs` | any generator must validate them strictly |
| `CODEOWNERS.example` omits `.semgrepignore`, `.gitleaks.toml`, `.trufflehog-exclude-paths.txt` | examples | files that silently narrow scans are unreviewed |
| POC `deploy.sh` adopts any role/table/secret that merely **shares a name**, and overwrites existing trust policies in place | POC `server/break-glass/infra/deploy.sh` | an unrelated resource named `break-glass-ci` would be taken over |
| POC broker trusts `context.repository` **from the CI payload** | POC `broker.mjs`, `request.mjs` | any holder of any invoker role can file a request labelled as another repository and have that repository's approvers decide it (Part E) |
| POC uses ONE invoker role trusted by a list of repositories | POC `deploy.sh` `OIDC_SUBJECTS` | per-repository revocation is impossible; the role's blast radius is every listed repo |

---

## Part B — Architecture

### B.1 Two tools, two trust boundaries

```
                 .ssd/onboarding.yml  (consumer-owned, NON-SECRET, CODEOWNED)
                           │
         ┌─────────────────┴──────────────────┐
         ▼                                    ▼
 ssd-onboard  (Phase 1)               ssd-onboard aws … (Phase 2/3)
 reads the repo, writes repo files    reads the config, talks to AWS
 NO AWS calls, NO GitHub mutations    NO repository file writes
 ─ init / inspect / validate          ─ doctor   (read-only)
 ─ render / render --check            ─ plan     (local IaC + unexecuted change set)
 ─ baseline status/prepare/accept     ─ apply    (one reviewed plan, exact account/region)
 ─ promote --enforce                  ─ verify   (read-only + negative checks)
```

The repository side can be run by any developer; its output is a pull request.
The AWS side requires a separately authenticated operator and produces cloud
changes only from a reviewed plan. Neither half calls the other. The only shared
artifact is the non-secret config file, and the only way AWS output reaches the
repository is a human copying a resulting ARN into that file (or, later, an
explicit `aws … --write-config` that prints a diff first).

### B.2 Source of truth

`.ssd/onboarding.yml`, schema version 1. It holds identifiers and decisions, never
credentials (see [onboarding-cli.md § configuration](onboarding-cli.md#configuration-reference)).
Enforcement:

- the schema is closed: an unknown key is an error, so there is no field in
  which a secret value could be recorded — only identifiers such as
  `githubSecretName` and ARNs exist;
- every string value is scanned for credential shapes (AWS access key IDs,
  `xox[bpas]-` Slack tokens, `hooks.slack.com` webhook URLs, GitHub tokens,
  PEM private keys) and refused;
- the serializer runs the same check before writing, so no command can persist one.

The file format is a **strict YAML subset** parsed by a dependency-free parser
(`onboarding/lib/yaml.mjs`): block mappings and sequences, quoted and plain
scalars, `true`/`false`/`null`. Every other scalar is a **string** (an AWS
account ID with a leading zero must never become a number). Anchors, aliases,
tags, flow collections and multiple documents are rejected rather than guessed.

### B.3 Rendering

`render` is a pure function: `(config, framework templates) → files`. It reads
nothing else from the repository, embeds no timestamp, and sorts nothing whose
order carries meaning, so identical input produces byte-identical output.

Each generated file begins with:

```
# GENERATED by ssd-onboard from .ssd/onboarding.yml. DO NOT EDIT BY HAND.
# Change .ssd/onboarding.yml, then run: ssd-onboard render
# ssd-onboard: generated schema=1 sha256=<digest of the body below>
```

**What the digest covers.** A generated file is exactly the three marker lines
(each ending in `\n`) followed by the *body*: every byte after the third line's
`\n`, as written — UTF-8, LF line endings, ending in `\n`. The digest is
`sha256(body)`. The marker lines are excluded, so the digest never covers itself.

**What it is for.** It is an **overwrite / drift guard only**: it lets `render`
tell a file it wrote from one a person edited, so a hand edit is never silently
clobbered. It is **not** a signature or a trust anchor — anyone can edit a file
and recompute it. What runs is trusted because of code review (CODEOWNERS on
`.github/workflows/` and `.ssd/`) and `render --check`, not because of this hash.

The digest lets `render` distinguish these cases on an existing file:

| Existing file | `render` | `render --check` |
| --- | --- | --- |
| marker present, digest matches | rewritten | fails if the new render differs (config changed, render not run) |
| marker present, digest **mismatch** (hand-edited) | refused; diff shown; `--force <path>` required | fails (drift) |
| no marker (human-owned) | refused; diff shown; `--adopt <path>` required | fails |
| absent | created | fails (missing) |

Unrelated workflow files are never read for writing, deleted or renamed. File
names are configurable; the **job name `security-gate` is not**.

### B.4 Profiles

| Profile | Generated | Capabilities declared to `_conformance.yml` |
| --- | --- | --- |
| `source-only` | `security.yml` | `library / none / none` |
| `container-self-managed` | `security.yml` (build + pre-push Trivy) | `container / none / self-managed` |
| `container-ecr-framework-gated` | `security.yml` + `deploy.yml` | `container / ecr / framework-gated` |

The ECR delivery file preserves the proven chain exactly: source recheck →
credential-free build (`no-cache`) → pre-push Trivy → `_ecr-collect.yml` (push+scan
role only) → immutable manifest digest → exact-digest registry scan →
`_artifact-gate.yml` (no credentials) → deploy of `repo@sha256:…` with the
**separate** SSM deploy role. The config validator refuses a push role equal to
the deploy role. Kubernetes/ECS/Argo/Jenkins targets are not modelled: those
repositories use `container-self-managed` until an adapter exists.

Every generated PR workflow contains the constant `security-gate` job (source for
`source-only`; source **and** image for containers, with `skipped` tolerated only
on the schedule) and the non-required `gate-mode` visibility job documented in
`onboarding.md §1.5`.

### B.5 Secure defaults the generator applies

| Decision | Default | Why |
| --- | --- | --- |
| gate mode | `log-only`, rendered as a **literal** | a mode change is a reviewed diff to config + workflow, not a variable flip |
| Semgrep roots | `.` | narrowing is allowed only with an explicit coverage warning |
| `.semgrepignore` | always explicit and managed (A.2) | absence is not "scan everything" |
| suggested ignores | only generated / vendored / build-output directories **that exist in the repo**, shown before acceptance | tests, migrations, IaC, scripts, config are never suggested |
| Gitleaks | no file → `gitleaks_config: ''` rendered explicitly | a later stray `.gitleaks.toml` cannot silently replace the ruleset |
| Gitleaks managed file | `[extend] useDefault = true` + consumer rules only | A.1 |
| existing `.gitleaks.toml` without `useDefault = true` | **blocks** | A.1 |
| TruffleHog | `trufflehog_exclude_paths: ''` rendered explicitly | no exclusions unless the owner names a file |
| TruffleHog include-paths | **not exposed** | the scan is over git history; an include-list is pure narrowing with no onboarding use |
| Slack | declared secret, notifier step only | A.5 |
| caller permissions | exactly the union of what the called workflow's jobs declare — checked against the pinned commit (less cannot start; more is an unnecessary grant) | GitHub validates reusable-workflow permissions statically |
| `id-token: write` on `source-security` | **never granted** (B.9) | generated callers use `_source-scan.yml`, in which no job can request a token; OIDC belongs to a dedicated `_break-glass-lambda.yml` caller, which Phase 1 does not generate (B.8) |
| break-glass | not generated (B.8) | there is no observed evidence to feed conformance |
| bootstrap | a `workflow_dispatch` checkbox, rendered only while the baseline is absent and the mode is log-only | runs a **full** scan (A.4), exists for one deliberate run, leaves no variable behind |
| Docker build args | none, ever | secrets in build args are baked into image history |

### B.6 Dependency coverage contract (option B, strict)

The inspector walks the repository's files (`git ls-files`; a filesystem walk
skipping `.git`/`node_modules` otherwise) and classifies each manifest with the
table in A.3. Only a **tracked** lockfile provides coverage: a CI checkout holds
nothing else, so an ignored or untracked lockfile is `uncovered` and covers no
manifest next to it.

| Class | Meaning | Generation |
| --- | --- | --- |
| `native+osv` | `package-lock.json` / `npm-shrinkwrap.json` of any npm dependency root (root or nested); root `requirements.txt` | allowed |
| `osv` (no native scanner exists) | `go.mod`, `Cargo.lock`, `Gemfile.lock`, … | allowed |
| `osv-unverified` | a lockfile OSV-Scanner documents but that was not verified against the pinned image (`composer.lock`, …) | allowed, with a warning |
| `workspace` / `covered-by-lockfile` / `no-dependencies` | covered through a lockfile, or declares nothing | allowed |
| `osv-only` | npm/PyPI file the language-native scanner does not read (nested `requirements.txt`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, a `package-lock.json` shadowed by an `npm-shrinkwrap.json`, an npm root refused as unsafe, …) | **blocked** |
| `osv-skipped` | a tracked lockfile that the repository's `.gitignore` rules match (`git ls-files --cached --ignored --exclude-per-directory=.gitignore`) and whose OSV coverage rests on the recursive walk, which skips it — any lockfile except an npm dependency-root lockfile, which is scanned by name (C.3). Reason shown: "tracked lockfile is ignored by Git rules and recursive OSV would skip it" | **blocked** |
| `uncovered` | a manifest nothing scans (`pyproject.toml` with deps and no lock, `setup.py`, `Pipfile`, `requirements/base.txt`, bare `package.json`) | **blocked** |

**There is no local override.** An earlier draft let an owned, expiring
acknowledgement in `.ssd/onboarding.yml` unblock a manifest. It was removed: the
expiry would have been enforced only when someone next ran `ssd-onboard`, while
the generated `security-gate` kept passing in CI indefinitely. A coverage
exception is only safe if the **runtime** path enforces it. A future version may
add one, designed as:

- a conformance-backed exception on a specific **control ID** (e.g.
  `dependency-scan`), read by `_conformance.yml` at every run;
- with **owner**, **reason** and **expiry**, validated like today's
  `security/exemptions.json`;
- **CI enforcement of expiry**: after the date the control fails in conformance
  and the report says why — exactly as exemptions already expire closed;
- scoped to named manifests, so a new unsupported manifest is not covered by an
  old exception.

That mechanism does not exist in this version and is not implemented here.

Option A — native scanners per dependency root, with the gate merging N reports —
is implemented for npm (C.3). It is not implemented for pip-audit or any other
ecosystem; those nested layouts stay blocked.

### B.7 Rollout / baseline state machine

State is derived, never stored twice:

| State | `rollout.gateMode` | `semgrep.baseline.state` | baseline file |
| --- | --- | --- | --- |
| `onboarding` | `log-only` | `absent` | absent |
| `candidate-downloaded` | `log-only` | `absent` | absent; `.ssd/candidates/semgrep-baseline.candidate.json` present |
| `baseline-accepted` | `log-only` | `accepted` | present, valid |
| `enforcing` | `enforce` | `accepted` | present, valid |
| **inconsistent** (validate fails) | any other combination — e.g. `accepted` with no file, a file with state `absent`, `enforce` without `accepted` |

```
init
  ▼
onboarding            (bootstrap checkbox rendered; gate log-only)
  │  dispatch the bootstrap run, then: baseline prepare --run <id>
  ▼
candidate-downloaded  (.ssd/candidates/, never the baseline path)
  │  human review, then: baseline accept   (type the finding count)
  ▼
baseline-accepted     (bootstrap checkbox removed; still log-only)
  │  promote --enforce                      (diff shown; no yes-default)
  ▼
enforcing             (delivery workflow generated for the ECR profile)
```

- **Provenance.** The bootstrap run writes
  `semgrep-baseline.candidate.provenance.json` beside the candidate
  (`security/scripts/baseline-provenance.mjs`), recording: schema version,
  repository slug and ID, the configured default branch, the exact scanned
  commit, ref and event, run ID and attempt, the framework repository and exact
  ref, the pinned Semgrep image and version, the Semgrep configs and paths, the
  sha256 of `.semgrepignore` (or `null`: Semgrep's built-in ignore list), the
  baseline path, that integrity was trusted and bootstrap active, the candidate's
  sha256 and finding count, and a digest over all of it (canonical JSON, sorted
  keys). It refuses to write a record for an untrusted or non-bootstrap run.
- `baseline prepare --run <id>` never writes the baseline path. Read-only, via
  `gh`, it requires the run to be a completed **`workflow_dispatch`** run of the
  configured workflow on the configured default branch (a full-tree scan —
  `pull_request`, `push`, `schedule` and other branches are refused; other
  branches are unsupported, not bypassable), the artifact to carry no
  `DO-NOT-BASELINE.txt`, the gate result to be trusted and a bootstrap, and the
  provenance to be intact (digest, candidate bytes, finding count), to agree with
  the run (run ID, commit, event) and with the config (repository, default
  branch, ref, framework ref, Semgrep configs and paths, baseline path).
- `baseline accept` runs every machine check before any human is asked:
  the repository must validate cleanly (including the framework binding, B.10);
  the baseline must not exist; the candidate must be intact against its
  provenance; and the provenance must match **this checkout** — origin
  repository, `HEAD` equal to the scanned commit, no uncommitted changes to
  tracked files, the current `.semgrepignore` hash, Semgrep configs and paths,
  and framework ref. Only then does it show every finding and require the
  finding count to be typed (or `--yes --expect-findings <n>`). Typing the count
  is a human checkpoint, not provenance. It records the scope digest it was
  accepted under.
- `promote --enforce` refuses unless the state is `baseline-accepted` and the
  baseline validates; it changes the config, re-renders, and prints the diff. It
  does not commit.
- Nothing in the tool writes a baseline for secret, dependency or image findings;
  the framework's baseline is Semgrep-only by construction.

### B.8 Break-glass is not generated (choice B)

The previous draft rendered `break_glass_enabled: true` and fed conformance a
hard-coded `"break-glass": {"status": "pass"}`. That is a fabricated result: a
configured ARN is not evidence the approval channel works. There is no reusable-
workflow output today that proves the control state, and the broker has an open
defect (E.2), so Phase 1 does not generate break-glass at all:
`breakGlass.mode` accepts only `disabled`, any other value is refused with an
explanation, and break-glass identifiers are not part of the schema. Generated
callers pass `break_glass_enabled: false` and never mention break-glass in
conformance evidence (the conformance report then records the control N/A with
its reason). Break-glass returns in Phase 3 together with an observed signal.

The shipped `examples/container-ecr/*.yml` still hard-code the break-glass PASS;
that is a documented gap in the examples, not in generated output.

### B.9 RESOLVED: OIDC least privilege for callers without break-glass

Desired invariant: a consumer with break-glass disabled receives no `id-token`
permission for source scanning. **Achieved in v1.2.0 by the source/break-glass
split.** Generated callers now grant `source-security` exactly:

```yaml
permissions:
  contents: read
  pull-requests: write
```

#### Why the grant existed, and why the fix had to take this shape

The reasoning below is kept because it is what `_source-scan.yml` exists for —
delete it and the twin looks like duplication.

- `_source-security.yml`'s `source-gate` job declares `id-token: write`. Its only
  consumer is the break-glass OIDC step, which runs only after eligibility and
  only with `break_glass_enabled: true`.
- GitHub validates a reusable workflow's job permissions **statically, when the
  run starts** — including jobs and steps that would not run (community
  discussions [#155062](https://github.com/orgs/community/discussions/155062),
  [#121112](https://github.com/orgs/community/discussions/121112); the live
  scratch consumer needed commit `b1738f6` to start at all). Minimal
  reproduction: [`docs/repro/oidc-static-permissions/`](repro/oidc-static-permissions/).
- So moving the break-glass steps to a separately conditioned job **inside**
  `_source-security.yml` does not help: that job's permission is still validated.
- The only thing that removes the grant is taking the OIDC-requesting job out of
  the workflow a break-glass-free caller calls. That is exactly what v1.2.0 did.

#### What shipped

| Workflow | OIDC | Who calls it |
| --- | --- | --- |
| `_source-scan.yml` | **none** — no job in it can request a token | **new callers, including every `ssd-onboard` render** |
| `_break-glass-lambda.yml` | `id-token: write` on its one job | a **dedicated** `break-glass` caller job, after `source-security`, only when an eligible BLOCK was delegated |
| `_source-security.yml` | `id-token: write` on `source-gate` | **legacy v1 callers only**, whose in-job Lambda break-glass path is a published v1 contract that cannot be removed within v1 (see [versioning.md](versioning.md#the-generated-oidc-free-twin)) |

`_source-scan.yml` is **generated** from `_source-security.yml`
(`node tools/render-source-scan.mjs`; the tests fail on drift), so the twin is a
build artefact rather than a fork — the scanner logic is not maintained twice.
Splitting enforcement across jobs was the cost: a BLOCK now fails in
`source-security`, and the caller's own `security-gate` job decides whether a
verified break-glass approval overrode it. At **v2**, the in-job Lambda path and
the twin both disappear and one file remains.

The contract checker (B.10) is generic over whichever callee a job names, so it
derived the new, smaller requirement without a rule change; its
`UNRESOLVED FRAMEWORK LIMITATION` warning now fires only for a caller still
pointed at `_source-security.yml`. The `todo` test that pinned the desired
invariant is gone, replaced by unconditional assertions in
`test/onboarding-render.test.js`.

**Not resolved by this:** Phase 1 still does not generate the dedicated
`break-glass` job at all — `breakGlass.mode` accepts only `disabled` (B.8), so a
generated caller has no OIDC anywhere in its source path. Wiring the break-glass
caller is currently a hand-written step, as in
`examples/container-ecr/security.yml`.

### B.10 Generator ↔ framework-ref binding, and how teams obtain the CLI

The generator is code at some framework commit X; the workflows it writes call
the framework at `framework.ref` Y. Generation, validation, acceptance and
promotion all require X = Y (`onboarding/lib/framework.mjs`):

- `framework.ref` must be an exact 40-character commit SHA (tags, even `vX.Y.Z`,
  can move; there is no moving-ref option);
- the CLI determines X with `git rev-parse HEAD` in its own checkout and refuses
  if it cannot (not a git checkout);
- the checkout must be **clean** (`git status --porcelain` empty, untracked files
  included), or its templates are not X;
- its `origin` must be `framework.repository`;
- reusable-workflow contracts (inputs, secrets, required permissions) are read
  from the immutable object `X:.github/workflows/<file>` via `git show` — never
  from `main`, `v1`, another ref, or the working tree. An unreadable contract is
  an error, not a pass.

There is no mode that validates against an arbitrary remote SHA the CLI is not
running from. **Supported invocation** (also in onboarding-cli.md):

```sh
git clone https://github.com/IamRitz/ssd-security-framework ssd-framework
git -C ssd-framework checkout --detach <reviewed-40-char-sha>
git -C ssd-framework rev-parse HEAD          # must print that SHA
node ssd-framework/onboarding/cli.mjs validate --repo <consumer-repo>
```

To move a consumer to a new framework commit: check the CLI out at the new SHA,
set `framework.ref` to it, run `render`, review the diff.

---

## Part C — Reusable-workflow API changes

### C.1 Made in this change: `slack_notify_webhook` secret (additive)

`_source-security.yml`, its generated twin `_source-scan.yml`,
`_break-glass-lambda.yml`, `_image-scan-prepush.yml` and `_artifact-gate.yml`
each declare an optional secret `slack_notify_webhook`. Two of those follow from
how the files relate rather than from a separate decision:

- **`_source-scan.yml` inherits the declaration.** It is rendered from
  `_source-security.yml` by `tools/render-source-scan.mjs`, so the secret block
  is copied mechanically and the tests fail on drift — it is never declared by
  hand, and the two cannot diverge.
- **`_break-glass-lambda.yml` accepts it for its notifier only.** That workflow's
  extra alert (the approval request was *not* delivered) needs the webhook.
  Its Lambda authentication is unchanged: a GitHub OIDC token exchanged for the
  invoker role, with **no broker secret of any kind**.

In every one of them the secret is referenced **only** in the notifier step's
`env:` (step scope), and takes precedence over `slack_notify_url`. When the legacy
input is non-empty, a warning names the problem without printing the value.
`slack_notify_url` keeps working (contracts are never removed within a major).
Callers pass it explicitly:

```yaml
secrets:
  slack_notify_webhook: ${{ secrets.SECURITY_NOTIFY_SLACK_URL }}
```

`_ecr-collect.yml` and `_conformance.yml` accept no secrets at all.

### C.1b Made in this change: baseline candidate provenance (additive)

The bootstrap step of `_source-security.yml` now also runs
`baseline-provenance.mjs` and uploads
`reports/semgrep-baseline.candidate.provenance.json` in `security-gate-results`
(B.7). No input or output changes. A framework commit without it produces
candidates `ssd-onboard` refuses ("there is no provenance record").

### C.2 Made in this change: bootstrap refuses a diff-aware scan

`bootstrap_baseline: true` now fails the run on `pull_request` and `push`
events (A.4), before the gate evaluates. This rejects input that was previously
accepted, and the versioning contract calls that breaking for producers. It is
made anyway because the accepted behaviour silently produced a wrong baseline;
fail-closed is the direction this framework resolves such conflicts. Onboarding
§1.1 now instructs `workflow_dispatch`.

### C.3 npm dependency roots (implemented)

An npm **dependency root** is a repository-relative directory holding a tracked
`package-lock.json` or `npm-shrinkwrap.json`, outside any `node_modules/`. When
a directory holds both, npm reads the shrinkwrap, so that is the root's lockfile
and the `package-lock.json` is `osv-only` (shadowed).

One function derives the roots — `discoverNpmRoots()` in
`security/scripts/dependency-roots.mjs` — and three readers use it:

| Reader | Uses it to |
| --- | --- |
| `npm-audit-roots.mjs` (dependency-scanning job) | run `npm audit --json --package-lock-only --prefix <root>` once per root, cwd `<root>`, via `execFile` (no shell) |
| `osv-npm-roots.mjs` (dependency-scanning job) | run the pinned OSV-Scanner once over exactly the root lockfiles, each named with `-L package-lock.json:/repo/<lockfile>` |
| `security-gate.mjs` (source-gate job, its own checkout) | require exactly one valid npm audit report per root |
| `onboarding/lib/inspect.mjs` → `coverage.mjs` | classify an npm lockfile `native+osv` only when it is a root's lockfile |

So `native+osv` in onboarding holds exactly when CI runs npm audit for that
lockfile's root and OSV-Scanner reads that lockfile.

**Two OSV-Scanner runs, one inventory.** The recursive backstop is unchanged
(`scan source --recursive --allow-no-lockfiles /repo`, all ecosystems,
`.gitignore` filtering on). The npm-root run is

```
docker run --rm -v <checkout>:/repo:ro <same pinned digest> \
  scan source --allow-no-lockfiles --format=json \
  -L package-lock.json:/repo/<root lockfile>   # one -L per npm dependency root
```

Pinned-image facts it rests on (`tools/verify-scanner-behaviour.mjs` § 3): `-L`
reads a tracked lockfile `.gitignore` lists; the `package-lock.json:` parse-as
prefix is always passed, because without it a `:` inside the path is misread as
a format prefix, and it reads `npm-shrinkwrap.json` too; `-L`
cannot share an invocation with a directory argument (exit 127); a missing path
exits 127; and a lockfile with no vulnerable package is **absent** from
`results`. So the run cannot show what it scanned, and its report is an envelope
declaring it, `reports/osv-scanner-npm-roots.json`:
`{ schemaVersion: 1, scanner, lockfiles: [...], exitCode, report }`. The gate
requires `lockfiles` to equal its own discovery, rejects any reported source
that is not one of them, and merges the results into the recursive report (a
lockfile both runs reported counts once). The scanner never decides the
inventory: a global `--no-ignore` was rejected because it would have let the
scanner's own walk, including any untracked file present at scan time, feed the
gate.

**No caller input.** The reusable workflows derive the roots from the checkout;
generated callers are unchanged and no permission changed. The `dependency_roots`
input sketched in an earlier draft was not needed.

**Tracked files only.** Roots come from `git ls-files --cached` (a filesystem
walk only outside a git work tree), so an ignored or untracked lockfile never
becomes a root.

**Untrusted paths.** A lockfile path that is absolute or contains an empty,
`.` or `..` segment, a backslash or a control character is refused. So is a
root whose directory components or lockfile is a symbolic link (the same "no
symbolic link anywhere" rule as `onboarding/lib/safe-path.mjs`), or one that
resolves outside the checkout. A refused root fails the npm audit step, is an
integrity failure of `dependency-scan` in the gate, and is `osv-only` (blocking)
in onboarding.

**Reports.** `reports/npm-audit.json` is still exactly npm's output for the
repository-root project. `reports/npm-audit-nested.json` holds every root below
it:

```json
{ "schemaVersion": 1, "scanner": "npm-audit",
  "roots": [ { "root": "frontend", "lockfile": "frontend/package-lock.json",
               "status": "valid", "attempts": 1, "report": { "…": "npm audit JSON" } } ] }
```

Every root is audited even when another fails; each is validated on its own.
The step fails if any root has no valid report. The gate re-derives the roots and
reports a `dependency-scan` integrity failure for a missing, failed, duplicated
or unexpected root. npm audit findings carry `location: <lockfile>` (for example
`frontend/package-lock.json`), so a finding names the root that produced it;
`security-gate.json` gains an additive `dependencyRoots.npm` list.

**Residuals:** npm honours a project `.npmrc` in each root (as it always did at
the repository root), so a repository can point its own audit at another
registry; this is documented, not changed, here. A tracked lockfile of any
OTHER ecosystem that `.gitignore` lists is skipped by the recursive OSV-Scanner
walk; ssd-onboard classifies it `osv-skipped` and blocks (B.6) rather than
scanning it by name — explicit per-file OSV support exists for npm roots only.
pip-audit remains root-only; pnpm/yarn workspaces, Poetry, Go, Cargo
and other multi-root layouts are not covered by this and remain blocked where
they were.

### C.4 Designed, not made: explicit empty-means-none for scanner config inputs

Today an empty `gitleaks_config` is already treated as "no file", so the
generator renders `''` explicitly and needs no API change. A future major could
flip the defaults of `gitleaks_config` / `trufflehog_exclude_paths` to `''`.

### C.5 Immutable OIDC subjects and ECR scanning ownership

Neither needs a reusable-workflow change: the workflows only consume a role ARN.
Both are Phase 2 concerns (D.4, D.5).

---

## Part D — Phase 2: `aws doctor / plan / apply / verify`

| Phase | Command | Status |
| --- | --- | --- |
| 2A | `aws doctor` | **implemented** — [D.10](#d10-phase-2a-as-implemented), [onboarding-cli.md § AWS readiness](onboarding-cli.md#aws-readiness-aws-doctor-phase-2a) |
| 2B | `aws plan` | **implemented** — [D.11](#d11-phase-2b-as-implemented), [onboarding-cli.md § AWS plans](onboarding-cli.md#aws-plans-aws-plan-phase-2b) |
| 2C | `aws apply` | **implemented** — [D.12](#d12-phase-2c-as-implemented), [onboarding-cli.md § Applying a plan](onboarding-cli.md#applying-a-plan-aws-apply-phase-2c) |
| 2D | `aws verify` | designed, **not implemented** (exit 2, contacts nothing) |
| 2E | `github …` | designed, **not implemented** |

D.1–D.9 are the reviewed design; D.10, D.11 and D.12 record where the
implementation refines it.

### D.1 Command contract

| Command | Mutates | Requires |
| --- | --- | --- |
| `aws doctor` | nothing | ambient AWS CLI credentials |
| `aws plan [--scope repo\|shared]` | writes `.ssd/aws-plans/<plan-id>/` locally; creates **unexecuted** CloudFormation change sets (a `CREATE` also leaves a `REVIEW_IN_PROGRESS` placeholder stack) | same, plus a clean framework checkout at `framework.ref` (D.11) |
| `aws apply --plan-id <id> --account <id> --region <r>` | executes exactly that change set | interactive typed confirmation of account **and** region, or `--yes` plus both flags; refuses on any mismatch |
| `aws verify` | nothing (plus explicitly listed controlled invocations) | same |

Every command starts with `aws sts get-caller-identity` and prints account,
region (`--region` flag > config > refuse; never the CLI's implicit default) and
caller ARN. It refuses when the account differs from `delivery.aws.accountId`,
and refuses a `:root` caller. No command reads, accepts or prints an access key;
credentials come only from the AWS CLI's own chain. All AWS calls go through one
`awsCli()` wrapper (execFile, argv array, JSON output, no shell) that has a
**read-only allowlist** (`describe-*`, `get-*`, `list-*`, `simulate-*`,
`sts get-caller-identity`, `cloudformation create-change-set` /
`describe-change-set` / `validate-template`) used by doctor/plan/verify; only
`apply` receives the mutating wrapper. A test asserts doctor/plan/verify cannot
reach a non-allowlisted verb. *(Refined in D.10/D.11: doctor's allowlist is
strictly read-only and plan has its own, separate planning allowlist.)*

### D.2 Ownership model

| Scope | Resources | Default | Change requires |
| --- | --- | --- | --- |
| **shared** (account/region) | GitHub OIDC provider; ECR registry scanning configuration; Inspector enablement; break-glass broker stacks (prod and synthetic) | discover, validate, report | `aws plan --scope shared` + `aws apply` of that plan |
| **per repository** | ECR repository; push+scan role; deploy role; break-glass invoker role; GitHub secret | `existing` (validate) or `managed` (stack) | `aws plan` + `aws apply` |

A resource is **managed** only if it is a physical resource of **the expected
CloudFormation stack** — the exact derived name (`ssd-delivery-<owner>-<repo>-<h8>`
per repository; `ssd-shared-github-oidc` / `ssd-shared-ecr-scanning` shared; see
D.10) in `delivery.aws.region` — whose stack tags carry `ssd:managed-by=ssd-onboard`,
`ssd:environment=production` and, for per-repo stacks,
`ssd:consumer-repository=<owner>/<repo>`. The name locates the owner; the tags
and state prove it. Phase 2B creates stacks only under these names. A resource that merely has the
expected name is reported `exists, not owned` and is never modified; the owner
chooses `existing` mode (validate only) or a CloudFormation **import** change set
that names it explicitly.

Tags on every managed resource and stack: `ssd:framework=ssd-security-framework`,
`ssd:managed-by=ssd-onboard`, `ssd:consumer-repository`, `ssd:environment`
(`production` | `synthetic`).

### D.3 Proposed file structure

```
onboarding/aws/
  cli.mjs                    aws doctor|plan|apply|verify dispatch
  identity.mjs               sts get-caller-identity, account/region/caller checks
  aws-cli.mjs                execFile wrapper; read-only vs mutating allowlists
  plan.mjs                   plan id, change-set creation, change classification   (2B: implemented, D.11)
  apply.mjs                  confirmation, re-verification, execute, wait          (2C: implemented, D.12)
  discover/
    oidc-provider.mjs        exists? thumbprints/audiences
    ecr.mjs                  repository, tag immutability, scan config coverage
    iam-role.mjs             trust + permission policies, simulate-principal-policy
    ssm.mjs                  managed instance, ping status, instance profile policies
    stacks.mjs               ownership by stack tags
  policy/
    trust.mjs                GitHub OIDC trust policy builder (exact subjects)
    evaluate.mjs             offline evaluator: StringEquals/StringLike over claims
    permissions.mjs          push+scan, deploy, invoker permission documents
  templates/
    shared-github-oidc.yaml
    repo-ecr-delivery.yaml   ECR repo (IMMUTABLE, scanOnPush, lifecycle), 2 roles
    repo-break-glass-invoker.yaml
    shared-break-glass.yaml  Phase 3
test/aws-*.test.js           fixture-driven: recorded CLI responses, no network
```

### D.4 OIDC subjects

- Candidates are built from `gh api repos/<o>/<r>` (`id`, `owner.id`) and
  `gh api repos/<o>/<r>/actions/oidc/customization/sub`:
  legacy `repo:<o>/<r>:<context>` and immutable
  `repo:<o>@<owner_id>/<r>@<repo_id>:<context>` (the format the POC's live
  repository actually receives).
- If customization is non-default or the format cannot be proven, `plan`
  refuses until `delivery.oidc.subjectFormat` is set explicitly **or**
  `delivery.oidc.observedSubject` is recorded from a probe (a one-job
  `workflow_dispatch` workflow that prints the claims, never the token — the
  POC smoke workflow's step, reused).
- Contexts: push+scan role `ref:refs/heads/<default branch>` only; deploy role
  `environment:<delivery.environment>` (the generated deploy job gains
  `environment:` so GitHub required reviewers can gate it); break-glass invoker
  `pull_request` + `ref:refs/heads/<default branch>`.
- Trust documents use `StringEquals` on `aud = sts.amazonaws.com` and an exact
  `sub` list. `StringLike`, `*` and org-wide subjects are rejected by the builder.
- Offline tests with the evaluator: correct repo/branch assumes; another repo,
  another branch, a fork `pull_request`, another environment, and the
  legacy/immutable format for the other mode are all denied — mutation-tested by
  swapping `StringEquals`→`StringLike` and appending `*`.

### D.5 ECR registry scanning (shared)

`get-registry-scanning-configuration` is read; coverage for the repository is
computed from existing rules (`WILDCARD` filters, `SCAN_ON_PUSH`/`CONTINUOUS_SCAN`,
BASIC vs ENHANCED). If not covered, the **shared** plan shows the full current
configuration and the proposed configuration = current rules + one filter for
this repository name, never a replacement. Repo-scope plans cannot contain this
change. Enhanced mode additionally reports Inspector status and the extra
`inspector2:ListCoverage/ListFindings` statement the push+scan role then needs.

### D.6 SSM

Validated, never created: the instance is SSM-managed and `Online`
(`describe-instance-information`), in the configured region/account; its instance
profile role has `AmazonSSMManagedInstanceCore` and ECR pull limited to the
repository. A missing permission produces a **proposed** policy document for the
owner of that role; the tool does not attach it (the instance role may serve an
unrelated production workload). The deploy role's `ssm:SendCommand` is limited to
that instance ARN and `AWS-RunShellScript`; `GetCommandInvocation` on `*`.

### D.7 Plans

A plan directory contains the rendered template, parameters, the change-set ARN,
`describe-change-set` output, and `plan.json` with account, region, caller ARN,
template sha256 and a plan id = sha256 of those. The plan summary lists creates,
updates (with replacement flag), deletes, and a separate section for every IAM
trust/permission document change rendered as a diff. `apply`:

1. re-runs identity checks and requires `--account`/`--region` to equal both the
   plan and the live caller;
2. re-describes the change set and refuses if it differs from the recorded one or
   is not `CREATE_COMPLETE`;
3. refuses deletes or replacements unless `--allow-destructive <n>` states their
   exact count;
4. executes, waits, and writes resulting outputs to the plan directory. It never
   edits `.ssd/onboarding.yml`; it prints the config diff to apply.

### D.8 GitHub configuration

`ssd-onboard github plan|apply` (separate from `aws`): the only value the
generated workflows need from GitHub is the optional Slack secret. `apply` reads
the webhook from hidden TTY input (or stdin when not a TTY) and pipes it to
`gh secret set <name> --repo <o>/<r>` on **stdin** — never argv, never logged.
Branch protection / rulesets (`security-gate` required, code-owner review, no
admin bypass) is a distinct `github protect` operation because it needs
repository administration.

### D.9 Tests required before Phase 2 ships

doctor is read-only (the wrapper records every argv; any mutating verb fails the
test); account and region mismatch abort apply; existing-resource discovery from
recorded responses; managed-vs-existing (name-only matches are never managed); no
repo-scope plan touches registry scanning; trust policies are repo/branch/
environment scoped (evaluator); invoker least privilege via recorded
`simulate-principal-policy` results; no secret values in templates, plans or logs.

### D.10 Phase 2A as implemented

What exists, and where it refines D.1–D.6:

- **Dispatch.** `cli.mjs` routes `aws` before any repository option parsing,
  through a *dynamic* import of `onboarding/aws/cli.mjs`. The static module graph
  of every repository command therefore contains no AWS code (asserted by
  `test/aws-doctor.test.js`).
- **Modules.** `aws/aws-cli.mjs` (the only process execution), `identity.mjs`,
  `doctor.mjs` (orchestration + pure checks), `report.mjs` (presentation through
  `lib/output.mjs`), `discover/{oidc-provider,ecr,inspector,iam-role,ssm,stacks,result}.mjs`,
  `policy/{evaluate,trust,permissions}.mjs`. (`plan.mjs` and `templates/` were
  added in Phase 2B, D.11; `apply.mjs` in Phase 2C, D.12.)
- **Allowlist (refines D.1).** Not verb prefixes: an explicit map of
  `service → operation → permitted flags`. Every flag takes exactly one value
  that must not look like an option, nor begin with `file://`, `fileb://` or
  `http(s)://` (AWS CLI parameter indirection; no operation opts in); lists are
  passed as one JSON argv element.
  The wrapper appends `--region <r> --output json --no-cli-pager` itself and sets
  `AWS_PAGER=''`, `AWS_CLI_AUTO_PROMPT=off`, `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true`.
  `cloudformation create-change-set` / `validate-template` are **not** in this
  allowlist; Phase 2B added a separate planning allowlist rather than widening
  doctor's (D.11).
- **Time and failures that end a run.** Each call gets min(60 s, the run's
  remaining 300 s budget). A timed-out call is `unverified`; a spent budget
  (`deadline`), an authentication failure (including an expired IAM Identity
  Center session or any error from the SSO credential operations), a missing CLI
  or an allowlist refusal ends the run as `ERROR`.
- **Discovery results** are `present | absent | unverified`; `absent` requires
  the specific not-found code for that call (e.g. `NoSuchEntity`,
  `RepositoryNotFoundException`, CloudFormation's `Stack for … does not exist`).
- **Outcomes.** `BLOCKED` (any FAIL) and `NOT_VERIFIED` (a check with
  `required: true` could not be proven) exit 1; `READY_WITH_WARNINGS` (WARN, or
  NOT VERIFIED only on `required: false` checks) and `READY` exit 0; `ERROR`
  (could not run) exits 1. Advisory checks are only the subject format, tag
  immutability and `existing`-mode ownership; human output labels them
  "(advisory)". Checks name their basis: `runtime`, `configuration`,
  `policy-document`, `policy-document+simulation`, `policy-document+runtime`.
- **Subject format (D.4).** Always NOT VERIFIED and not `required`: doctor makes
  no GitHub call. The trust evaluator accepts the legacy format by exact match
  and the immutable format only with a WARN that the IDs are unverified.
- **Scanning mode.** No config field declares BASIC vs ENHANCED; the registry's
  own `scanType` decides whether Inspector is checked and whether the push role
  needs the `inspector2` statement. No schema change was needed for Phase 2A.
- **Stack names (D.2)** are derived in `aws/stack-names.mjs`, not configured:
  `ssd-delivery-<display>-<h8>` with `<h8>` = sha256 of the canonical
  `github.com/<owner>/<repo>` (lower-cased: GitHub names are case-insensitive),
  and the two fixed shared names. Ownership binds to the exact name; another
  correctly tagged ssd stack is not the owner.
- **`ssd:environment` (D.2)** is the stack's class, not `delivery.environment`
  (the GitHub environment). Phase 2 delivery stacks are `production`, and
  ownership requires exactly that; `synthetic` is the Phase 3 break-glass test
  stack (E.4).
- **SSM (D.6).** The instance role is found through `ec2 describe-instances` →
  instance profile → its single role, never by name. `Online` is runtime proof
  of SSM core; ECR login + pull on the repository is analysed, and a missing
  grant prints a proposed policy for the role owner.


### D.11 Phase 2B as implemented

What exists, and where it refines D.1–D.7:

- **Modules.** `aws/plan.mjs` (orchestration), `aws/plan/scope.mjs` (the
  repo/shared boundary), `aws/plan/change-set.mjs` (validate, create, poll,
  classify), `aws/plan/record.mjs` (plan id, persisted-secret check, plan
  directory), `aws/policy/diff.mjs` (semantic IAM diff),
  `aws/templates/{common,repo-ecr-delivery,shared-github-oidc}.mjs`,
  `aws/plan-report.mjs`. Builders were added beside the evaluators they must
  satisfy: `buildTrustPolicy` in `policy/trust.mjs`, `rolePolicyDocument` in
  `policy/permissions.mjs`, `mergeScanningRules` in `discover/ecr.mjs`,
  `discoverStackByName` / `discoverStackResources` / `planStack` in
  `discover/stacks.mjs`. `plan/record.mjs` is the only module under
  `onboarding/aws` that writes a file; doctor's module graph never reaches it
  (asserted).
- **Two allowlists (refines D.1).** `readOnlyAws()` keeps the Phase 2A table
  byte for byte. `planningAws()` is the read-only table plus
  `cloudformation validate-template`, `create-change-set`,
  `describe-change-set` and `describe-stack-resources --stack-name`. Planning
  flags whose value matters are checked by value: change-set type
  `CREATE|UPDATE`, derived stack names, `ssd-plan-<64 hex>` change-set names,
  only `CAPABILITY_NAMED_IAM`, only SSD tags, inline JSON template bodies of at
  most 51,200 bytes. There is no `execute-change-set`, no stack create/update/
  delete, no `delete-change-set`, no import (`IMPORT`, `--resources-to-import`,
  `--import-existing-resources`), no `--template-url`/`--role-arn`/
  `--notification-arns`. The template reaches the CLI as one argv element,
  never as a file reference; the `file://`/`fileb://`/`http(s)://` refusal
  stays in force for every value.
- **Framework binding.** `aws plan` refuses unless `frameworkProblems()`
  (`lib/framework.mjs`, the `render` rule) is empty: a clean checkout whose
  origin is `framework.repository` at exactly `framework.ref`. Templates are
  code, so this is what makes "same config + same framework commit →
  byte-identical template" meaningful.
- **Templates (refines D.3).** JSON rendered by code, not static YAML: the
  policies come from the canonical builders, which refuse to return a document
  the doctor's evaluators would not accept (trust: `accepted` with no warning;
  permissions: `PASS`). No CloudFormation parameters, outputs, conditions or
  transforms. Every resource is `DeletionPolicy: Retain` /
  `UpdateReplacePolicy: Retain` and SSD-tagged. **No lifecycle policy** (D.3
  listed one; none is designed or configurable, and an implicit retention
  policy could expire a rollback image). The OIDC provider has no thumbprint
  (`ThumbprintList` is optional in the CloudFormation schema).
- **Stacks.** One plan id = one stack = one change set; `--scope shared` can
  produce several independent plans. Phase 2B plans `ssd-delivery-…` (repo)
  and `ssd-shared-github-oidc` (shared). `ssd-shared-ecr-scanning` has a
  reserved name but **no template**: see the next item.
- **Registry scanning (refines D.2, D.5).** New closed-schema field
  `delivery.registryScanning: existing | managed` (default `existing`).
  `existing`: discovered, validated and reported, with the D.5 proposal
  (current rules + one filter, scan type unchanged) shown but never planned.
  `managed` **blocks** in Phase 2B. Verified against the CloudFormation
  resource schema and the ECR API: `AWS::ECR::RegistryScanningConfiguration`
  exists, is keyed by the registry id, and create/update call
  `PutRegistryScanningConfiguration`, which replaces the whole configuration;
  but its `ScanFrequency` cannot express `MANUAL` (an existing MANUAL rule
  would be lost), its handlers hold `inspector2:Enable`/`Disable` (a change
  can toggle Inspector), it is not taggable, its create behaviour on an
  already configured registry is undocumented, and its provider source is not
  public. That is not safe to plan.
- **Inspector (refines D.2).** No CloudFormation resource type enables
  Inspector v2; it is reported as a prerequisite of ENHANCED scanning, never
  planned.
- **Ownership and change-set type.** The D.2/D.10 ownership model, reused
  (`evaluateOwnership`; the stack-tag half is shared as `stackTagProblems`).
  `planStack` decides the type from the exact expected stack: absent →
  `CREATE`; an SSD-tagged `REVIEW_IN_PROGRESS` placeholder (left by an earlier
  unexecuted `CREATE`) → `CREATE`; settled, successful, SSD-tagged → `UPDATE`;
  anything else blocks. A managed resource that exists but is not a physical
  resource of the expected stack, under the expected logical id, blocks
  (`exists-not-owned`; a future import flow is needed). Push and deploy role
  names equal case-insensitively, or a live role matching only
  case-insensitively, block. A stack holding an unexpected resource blocks. A
  stack-owned `managed` role with any policy the stack does not represent — a
  managed policy attached directly, or an inline policy other than the stack's
  `ssd-push-scan` / `ssd-deploy` — blocks (`unmanaged-policy`, naming the ARN or
  name): its effective permissions would differ from the reviewed change set.
  An incompletely readable policy list blocks too (`policies-unverified`).
  Nothing is detached. Every block happens before any change set is created.
- **Plan id (refines D.7).** sha256 of canonical JSON over account, region,
  scope, stack kind and name, change-set type, base stack (`{state: absent}` or
  `{state: present, stackId, stackStatus, lastUpdatedTime}`), template /
  parameters / tags sha256, capabilities, framework repository and ref, and the
  consumer repository. The caller ARN is **recorded** in `plan.json` but is
  not part of the id (D.7 included it; a session name is incidental). The
  change-set name is `ssd-plan-<plan id>`; a change set of that name that
  already exists (its local directory lost) is refused, never replaced.
  Executing any change set removes a stack's other change sets, so a later plan
  of the same inputs can be recreated after an apply.
- **Change-set lifecycle.** `validate-template` (no transforms, no
  parameters, capabilities ⊆ named IAM) → `create-change-set` →
  `describe-change-set` polled with 1/2/3/5/8/10 s backoff inside the run's
  300 s budget, at most 60 polls. `CREATE_COMPLETE` + `AVAILABLE` is a plan;
  `FAILED` with CloudFormation's documented no-change reason is
  `outcome: no-changes` (recorded, never applicable); anything else fails. The
  described document must be exactly the created change set (name, id, stack,
  tags, capabilities, no parameters, no nested stacks, no
  `ImportExistingResources`, no `NextToken`). `Add`→CREATE, `Remove`→DELETE,
  `Modify` with `Replacement` `True`/`Conditional`→REPLACE, `False`→UPDATE;
  `Dynamic`, `Import` and anything else fail closed. DELETE and REPLACE are
  destructive and counted separately; the scope boundary is asserted on the
  template and again on the described changes.
- **Plan directory (refines D.7).** `.ssd/aws-plans/<plan-id>/` holds
  `template.json`, `parameters.json`, `change-set.json`, `policies.json`
  (IAM before/after + semantic diff) and `plan.json` (written **last**,
  carrying every other file's sha256). Created through `lib/safe-path.mjs`
  (no `..`, no symbolic link anywhere), exclusively, files `O_EXCL|O_NOFOLLOW`.
  The slot is proven free before any AWS object is created. All five files
  are checked for credential shapes before the directory is created; a match
  refuses the plan, nothing is redacted and kept. `inspectPlanDirectory()` is
  the local half of a future apply's check: a directory without a consistent
  `plan.json`, with a file whose hash differs, or with `outcome: no-changes` is
  never applicable.
- **OIDC subjects (refines D.4).** No GitHub API call: generated trust uses
  exact legacy subjects only; the subject format remains NOT VERIFIED, as in
  doctor. `delivery.oidc.subjectFormat` / `observedSubject` were not added.
- **Residual.** A `CREATE` change set leaves a `REVIEW_IN_PROGRESS` placeholder
  stack, and no-change change sets remain `FAILED` objects, until deleted
  outside ssd-onboard (plan has no delete permission by design). The base
  revision binds `LastUpdatedTime`, which AWS sets; apply re-describes the
  stack and refuses a stale plan (D.12).


### D.12 Phase 2C as implemented

What exists, and where it refines D.1 and D.7:

- **Modules.** `aws/apply.mjs` (orchestration and the wait),
  `aws/apply/plan-check.mjs` (pure local checks: record consistency, intent,
  destructive count), `aws/apply/live.mjs` (pure live decisions: change-set and
  template comparison, stack time-of-check/time-of-use, terminal states),
  `aws/apply-report.mjs`. `plan/record.mjs` stays the only writer under
  `onboarding/aws`: it gained `readPlan` (the hash-verified texts),
  `applyRecordsOf`, `writeApplyRecord` and `configDigestOf`.
- **Command (D.1).** `aws apply --plan-id <id> --account <id> --region <r>
  [--allow-destructive <n>] [--yes] [--json]`. All three of plan id, account
  and region are required in **both** modes (D.1 required them with `--yes`;
  interactive mode requires them too, so the operator always states the target
  before seeing it). Interactive confirmation is typing the account id and then
  the region exactly; `--yes` skips only the typing. With neither a terminal
  nor `--yes`, apply refuses before AWS.
- **Third wrapper (refines D.1).** `applyAws({ binding })` is created for one
  plan. Its reads accept only that plan's exact stack name / stack id /
  change-set ARN (`sts get-caller-identity`; `cloudformation describe-stacks`,
  `describe-change-set`, `get-template --template-stage Original`,
  `describe-stack-resources`). Its single mutation is
  `aws.executeChangeSet()`: the fixed argv
  `cloudformation execute-change-set --stack-name <name> --change-set-name <ARN>`,
  at most once per wrapper; the generic call path cannot express it. No
  `--role-arn`, `--client-request-token`, `--disable-rollback`,
  `--retain-except-on-create`; no other mutation. `readOnlyAws()` and
  `planningAws()` are unchanged. `get-template` is an addition to D.7: the
  describe document does not carry the template, so it is the only way to prove
  the live change set holds `template.json`.
- **Local verification (refines D.7).** `plan.json` itself is not hashed; the
  plan id binds `planIdInput`. So apply (a) recomputes every file hash and the
  tags hash, (b) requires every copy in `plan.json` to equal `planIdInput`, and
  (c) re-derives every field the id does not bind — the change-set ARN and
  name, the stack id (for a `CREATE`, the placeholder's), the classified
  changes, counts and destructive count — from the hash-verified
  `change-set.json`. Nothing in `plan.json` is trusted on its own.
- **Intent.** `--account` = plan = `delivery.aws.accountId` = live caller
  account; `--region` = plan = `delivery.aws.region`; repository and stack name
  re-derived from the current configuration; the configuration digest equals
  `createdFromConfigDigest` (a plan reviewed against another configuration is
  stale); `frameworkProblems()` empty and the plan's framework ref is
  `framework.ref`.
- **Caller (D.7 vs D.11).** D.7 bound the caller ARN; D.11 removed it from the
  plan id. Apply keeps D.11: any non-root principal of the plan's account may
  apply; planner and applier ARNs are both shown and recorded.
- **Change set (D.7 step 2).** Re-described by its recorded ARN and compared
  with `change-set.json` as whole canonical documents — Phase 2B normalizes no
  metadata, so neither does apply; a field present in one and not the other
  also refuses. Only `CREATE_COMPLETE`/`AVAILABLE` executes. The destructive
  count is recomputed from the live description.
- **Stack time-of-check/time-of-use.** UPDATE: live stack id, status and
  `LastUpdatedTime` equal the base revision. CREATE: the live stack is the
  `REVIEW_IN_PROGRESS` placeholder with the recorded stack id (and, when planned
  against an existing placeholder, the same revision). Both: SSD ownership tags
  still present. All live checks run before confirmation **and again** after it,
  immediately before execution.
- **Destructive (D.7 step 3).** `--allow-destructive <n>` must equal the
  recorded and the fresh count; none needs no flag (`0` accepted); no boolean.
- **Execution and wait (D.7 step 4).** `apply-started.json` is written
  exclusively before `execute-change-set` (a crash afterwards still blocks a
  rerun; AWS blocks one too, the change set no longer being `AVAILABLE`). The
  stack is polled by stack id with backoff up to 15 s, inside a 30-minute wait
  budget separate from the 300 s pre-flight budget. Success is only
  `CREATE_COMPLETE` (CREATE) or `UPDATE_COMPLETE` with a newer
  `LastUpdatedTime` (UPDATE) on the same stack id; a rollback, failure, delete,
  other stack id or unknown state is `APPLY_FAILED`; a timeout, lost
  credentials or unreadable stack is `APPLY_FAILED` with `observed: false`. An
  `execute-change-set` that AWS rejects is `APPLY_FAILED` (`accepted: false`)
  and is not polled.
- **Outcomes.** `APPLIED` (exit 0); `REFUSED`, `ERROR` (before execution) and
  `APPLY_FAILED` (exit 1, distinguished by the JSON `outcome`) — the existing
  0/1/2 convention, with no new exit code.
- **Records (D.7 step 4).** `apply.json` holds non-secret evidence (identities,
  stack, change set, operation, final status, redacted reason, counts, outputs,
  resources). Both apply records are exclusive and secret-checked; AWS text is
  redacted with the run's credential environment before display or recording.
- **Configuration (D.7).** Apply never edits `.ssd/onboarding.yml`. The
  generated templates have no outputs and create resources under the names the
  configuration already holds, so the printed "config diff" is normally empty;
  a physical id that differs from the configuration is printed as a manual
  change.
- **Residual.** (1) Drift **outside** the stack between plan and apply (e.g. a
  policy attached by hand to a stack-owned role) is not re-discovered; plan's
  discovery is not repeated, and the base-revision check only covers the stack.
  (2) A rejected or failed apply spends the plan; because plan ids are
  deterministic, re-planning an unchanged stack collides with the existing plan
  directory and change set, which must be removed outside ssd-onboard. (3)
  `REVIEW_IN_PROGRESS` placeholders of abandoned CREATE plans and failed stacks
  are not cleaned up (no delete permission by design). (4) Full-document
  change-set equality means an AWS CLI upgrade that adds a field between plan
  and apply forces a re-plan.

---

## Part E — Phase 3: break-glass provisioning

Not implemented. Design:

### E.1 Architecture kept

Shared: CI broker Lambda (no URL, IAM invoke only), interaction Lambda (the one
public Function URL, Slack HMAC is the authentication), DynamoDB table with
conditional-write claims, Secrets Manager. Per repository: an invoker role that
may invoke only the CI broker, and an approver mapping. Lambda transport remains
preferred; the HTTP transport is not generated.

### E.2 Concrete defect to fix first: caller-asserted repository

The CI broker stores `context.repository` from the invoke **payload**, and the
interaction handler authorizes approvers against that stored value. Lambda direct
invocation does not expose the caller's IAM identity to the function, so today any
principal able to invoke the broker can create a request that claims to be
another repository, and that repository's approvers are the ones asked. With
per-repository invoker roles this becomes cross-repository request forgery.
(Verified in the POC: `request.mjs` stores `payload.context` verbatim after a
format check only.) It also reaches beyond approvals: after a decision the
broker posts its audit comment to `context.repository`'s pull request with its
own GitHub credential, so a forged request makes the broker comment on another
repository's PR.

Fix (broker change, prerequisite for multi-repo onboarding): the `source-gate`
job already holds `id-token: write`; it requests a second GitHub OIDC token with a
dedicated audience (e.g. `ssd-break-glass`) and includes it in the notify
payload. The broker verifies it (RS256 against GitHub's JWKS, `iss`, `aud`, `exp`)
and derives `repository`, `repository_id`, `ref`, `run_id` **from the token**,
rejecting any payload context that disagrees. The approver map is then keyed by
the immutable `repository_id`.

### E.3 Per-repository onboarding without touching the shared stack

Approver mappings move out of the interaction function's environment (changing it
is a shared-resource mutation per repo) into per-repository SSM parameters,
`/ssd/break-glass/<environment>/approvers/<repository_id>` (a JSON list of Slack
user IDs), read with `ssm:GetParameter` on that path prefix only. Onboarding a
repository = one per-repo stack: its invoker role + its parameter. The interaction
function's missing/malformed parameter semantics stay fail-closed (nobody authorized).

### E.4 Production vs synthetic

Two separately named and separately tagged shared stacks
(`ssd-break-glass-production`, `ssd-break-glass-synthetic`), each with its own
functions, table, secrets and Slack app. Plan refuses when the synthetic and
production function ARNs, invoker role ARNs, tables, secret ARNs or Slack
channel IDs coincide, and when a synthetic stack's parameters reference a
production-tagged resource. Phase 1's config deliberately holds no break-glass
identifiers (B.8); Phase 3 reintroduces production and synthetic identifiers as
separate fields and refuses equal values (the reusable workflow already does).

### E.5 Secrets

The Slack bot token, Slack signing secret and (while it exists) the GitHub audit
credential are created as `AWS::SecretsManager::Secret` resources **without** a
value; `aws apply` then prompts with hidden input (or reads stdin) and calls
`put-secret-value --secret-string file:///dev/stdin`, or the owner supplies an
existing secret ARN. No value appears in config, templates, change sets, plans,
argv or logs.

### E.6 GitHub PAT vs GitHub App (trade-off, not changed)

| | Fine-grained PAT (today) | GitHub App |
| --- | --- | --- |
| identity on the audit comment | a person | a bot |
| lifetime | long-lived, manual rotation | 1-hour installation tokens minted per use |
| scope | repositories the person can access | repositories the app is installed on, per permission |
| offboarding | breaks when the person leaves | independent of people |
| broker complexity | none | JWT signing with the app private key (Node `crypto`), token exchange |

Recommendation: move to a GitHub App with `pull_requests: write` only, private key
in Secrets Manager, in a dedicated broker change. Not silently redesigned here.

### E.7 Verification

`aws verify --break-glass` must include, per repository invoker role, negative
checks via `iam simulate-principal-policy` (read-only) **and** a GitHub-run probe
job (the POC smoke workflow's pattern, holding the real OIDC session):

- `lambda:InvokeFunction` on the interaction function → denied
- `dynamodb:GetItem/PutItem/UpdateItem` on the table → denied
- `secretsmanager:GetSecretValue` on every broker secret → denied
- `lambda:GetFunction` / `UpdateFunctionConfiguration` on the broker → denied
- positive: `lambda:InvokeFunction` on the CI broker with a synthetic request, **only
  against the synthetic stack**

plus the POC `verify-live.mjs` suite (unsigned/tampered/stale/wrong-secret
rejections, unauthorized and other-repo approver no-ops, concurrent-claim race,
timeout), run only against the synthetic stack and using its own signing secret.
