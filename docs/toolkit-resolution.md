# How the toolkit reaches a consumer that has none of it

This is the mechanism the whole extraction rests on. It is written down because
the obvious implementations are subtly wrong, and because a regression here is
invisible: the pipeline still goes green while scanning the wrong tree.

## The problem

Every reusable workflow runs `node <toolkit>/scripts/*.mjs`. Before extraction,
that path resolved against the **calling repository's** checkout, which worked
only because the workflows and the scripts lived in one repository. A consumer
repo has no `security/scripts/` directory, so every gate step would fail on a
missing file.

The scripts also need a policy, and the ECR collector needs its fixtures. None
of that can be assumed to exist in a consumer.

## The mechanism

Each job does three things before anything else runs:

```yaml
- uses: actions/checkout@<sha>          # the consumer, at the workspace root
  with: { persist-credentials: false }

- uses: actions/checkout@<sha>          # this framework
  if: ${{ inputs.toolkit_path == '' }}
  with:
    repository: ${{ inputs.toolkit_repository }}
    ref: ${{ inputs.toolkit_ref }}
    path: .ssd-toolkit-checkout
    persist-credentials: false

- run: |                                 # move it OUT of the scanned workspace
    mv .ssd-toolkit-checkout "$RUNNER_TEMP/ssd-toolkit"
    # ... assert VERSION major, then export SSD_TOOLKIT
```

Every subsequent step invokes scripts as `$SSD_TOOLKIT/scripts/x.mjs`. The
working directory stays the consumer's checkout, so the scripts' own
CWD-relative defaults (`reports/…`) land in the consumer's tree exactly as
before. Consumer-owned paths — the Semgrep baseline, an optional `policy_path` —
stay relative to the consumer. Nothing else changed.

## Why the relocation is a control, not tidiness

**If the toolkit stays in the workspace, the scanners scan the framework.**

- **Semgrep**'s default scan path is `.`. The framework's own `.mjs` scripts
  would be scanned with the *consumer's* rulesets, and any finding reported
  against the consumer's code. A consumer would be blocked by a finding in code
  it does not own and cannot fix.
- **OSV-Scanner** runs `scan source --recursive` over the whole tree. Any
  manifest the framework ships would be resolved and reported as the consumer's
  dependencies.
- Gitleaks and TruffleHog scan *git history* (`git /repo`), so an untracked
  subdirectory is invisible to them. They are the reason this is easy to miss:
  two of the four scanners are unaffected, so a broken relocation looks fine
  until Semgrep or OSV reports something strange.

Moving the checkout under `$RUNNER_TEMP` leaves `$GITHUB_WORKSPACE`
byte-identical to the consumer's own checkout. `_source-security.yml` then
asserts this explicitly in each of its three scanner jobs — if
`.ssd-toolkit-checkout` still exists, the job fails rather than scanning it.

`actions/checkout` refuses a `path` outside the workspace, which is why this is
a checkout followed by a `mv` rather than a checkout straight to the right
place.

## Why not have the workflow reference its own commit

The appealing design is for the reusable workflow to check out *exactly the
commit it was called at*, removing any possibility of version skew and any need
for a `toolkit_ref` input.

**This is not possible.** `job_workflow_ref` and `job_workflow_sha` — the values
that identify the reusable workflow file and commit — exist only as **OIDC token
claims**. They are not exposed as `github.*` expression contexts. The contexts
that do exist, `github.workflow_ref` and `github.workflow_sha`, describe the
**caller's** workflow, so using them would check out the consumer's repository
at the consumer's commit: the original bug, restored.

A job could request an OIDC token and parse `job_workflow_sha` out of it, but
that would force `id-token: write` onto credential-free scanner jobs purely to
learn a version number — trading a real credential-boundary guarantee for a
convenience. That is the wrong trade.

So the ref is stated as an input, and the risk is contained by asserting the
toolkit's major version after checkout. See
[`versioning.md`](versioning.md#the-toolkit_ref-duplication-and-why-it-exists).

## Access requirements

`actions/checkout` fetching a second repository uses the job's `GITHUB_TOKEN`,
which can read **public** repositories. If this framework is private, consumers
need a token with access to it, passed explicitly — which also means a public
consumer cannot call a private framework's reusable workflow at all. Keeping the
framework public is the simplest correct configuration.

## The vendored escape hatch

`toolkit_path` points at a toolkit already present in the caller's checkout.
When set, no framework checkout happens and the path is used verbatim.

It exists for two cases: a repo with a deliberate vendoring policy, and
debugging a toolkit change against a real consumer before releasing it. It is
not the normal path — a vendored copy is a copy, and copies drift, which is the
problem this framework exists to solve.

## What this does not solve

- **The consumer still owns its Semgrep baseline.** It cannot be centralized:
  it is a record of *that repo's* accepted findings. A missing baseline is a
  fail-closed report-integrity BLOCK, not a pass.
- **The consumer still owns its build.** The framework scans an image tarball
  the caller produced; it does not know how to build anyone's software.
- **Scanner images are pulled per job.** Each job pulls the scanner images it
  needs by digest; the toolkit checkout adds a second small clone per job. Both
  are cheap relative to the scans themselves.
