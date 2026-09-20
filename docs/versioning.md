# Versioning: what moves, what is frozen, and why they differ

Three layers of this framework have three different mutability needs. Applying
one rule to all three would be wrong in two of them.

| Layer | Pinned how | Moves when | Why |
| --- | --- | --- | --- |
| The reusable workflow a consumer calls | `@v1` (moving major tag) | every patch and minor release | A central fix must reach every consumer without a PR per repo. That is the entire reason the framework exists. |
| Scanner container images | `@sha256:…` digest | only by an explicit, reviewed commit here | A scanner is *code that runs in CI*. A moving tag means a third party can change what executes inside your pipeline between two runs of the same commit. |
| Third-party actions (`actions/checkout`, `aws-actions/…`) | full commit SHA | only by an explicit, reviewed commit here | Same argument. A release tag can be repointed at different code. |

The pattern: **the layer you own moves, the layers you do not own are frozen.**
A consumer accepts central fixes from this repository because it has a review
relationship with it. It has no such relationship with the Semgrep image
publisher, so that one is pinned by digest and upgraded deliberately.

## Tags published here

| Tag | Mutability | Use |
| --- | --- | --- |
| `v1` | moves to each `v1.x.y` release | **Default for consumers.** Central fixes arrive automatically. |
| `v1.0.0` | immutable | Pin when a repo must not change without a PR — a regulated pipeline, or while bisecting a CI regression. |
| a commit SHA | immutable | Maximum strictness. You give up central fixes entirely. |

Breaking changes get `v2` and a new major tag. `v1` never becomes `v2`.

Contracts are treated as a published API: **add inputs with defaults, never
rename or repurpose an existing one.** An input whose meaning changes under a
consumer is a silent breakage, which is worse than a loud one.

## Machine-readable schemas are contracts too

Workflow inputs and outputs are the obvious contract, but they are not the only
one. Anything this framework **documents** as machine-readable — the normalized
registry report a collector emits, the gate result, the conformance report, the
Semgrep baseline file — is consumed by something, and is therefore subject to
the same rules:

| Change | Compatibility |
| --- | --- |
| Adding an **optional** field | **compatible** — a reader that ignores it is unaffected |
| Adding a new **enum value** to an existing field | **breaking** for any reader that exhaustively switches on it; treat as breaking unless the field is documented as open |
| Removing or renaming a field | **breaking** |
| Changing the **meaning**, type, or units of an existing field | **breaking**, and the worst kind — it fails silently |
| Tightening validation so previously accepted input is rejected | **breaking** for producers |

"Nobody reads that field" is an assumption, not a fact. If a field is documented,
assume it is parsed.

**Report schemas carry their own `schemaVersion`, independent of the framework
tag.** A report is data that outlives the run that produced it: it gets stored,
diffed, and read by tooling that was not necessarily built against the same
framework release. So:

- A reader must check `schemaVersion` before interpreting a report, and refuse a
  major it does not understand rather than guessing at the fields it recognises.
- Bumping a report's `schemaVersion` is **not** automatically a framework major.
  The framework's version tracks its *workflow* contract; a report schema tracks
  its own shape. They move independently and on purpose.
- Conversely, a framework major does **not** implicitly bump a report schema.

The producing side must fail closed on a schema it does not recognise. This is
already how `image-gate.mjs` treats the normalized registry report: an unknown
`source` is a report-integrity `BLOCK_DEPLOY`, never a best-effort parse.

## The generated OIDC-free twin

`_source-scan.yml` is **generated** from `_source-security.yml`
(`node tools/render-source-scan.mjs`), and the tests fail if the committed copy
is stale. It exists because of a v1 constraint, not a preference:

- `_source-security.yml` has shipped an in-job Lambda break-glass path, and the
  `id-token: write` it needs, since `v1.0.0`. Existing callers rely on it.
- GitHub validates a called job's permissions statically, so that one line
  makes every caller grant OIDC — even with break-glass disabled.
- Removing it in place would silently stop existing Lambda callers' approvals
  (a v1 semantic break). Nesting one reusable workflow inside the other depends
  on `./` resolution that GitHub does not document for nested cross-repository
  calls, and still could not keep `needs.source-security.result == success` for
  an approved override.

So `_source-security.yml` keeps its v1 behaviour, and new callers use the twin
plus `_break-glass-lambda.yml`. The twin is a build artefact, not a fork: edit
only `_source-security.yml`, re-render, commit both. At **v2**, delete the
in-job Lambda path and the twin collapses back into one file.

## Strict break-glass evidence: opt-in in v1, unconditional in v2

Rejecting the v1 conformance input `"break-glass": {"status": "pass"}` would be a
producer-breaking change (see the table above). So:

| | v1 | v2 |
| --- | --- | --- |
| `_conformance.yml` `strict_break_glass_evidence` | new input, default **`false`** | removed; strict is the only behaviour |
| status-only `break-glass` evidence | accepted exactly as before, with a loud deprecation warning | rejected |
| structured evidence from `_break-glass-lambda.yml` | available and **recommended**; every shipped `_source-scan.yml` example sets `strict_break_glass_evidence: true` | required |
| source-gate `override` | honoured only in strict mode, and only when proven | honoured only when proven |

No existing v1 caller changes result because of this. A caller migrates by
setting `strict_break_glass_evidence: true` and feeding the structured
`break-glass` record.

## The `toolkit_ref` duplication, and why it exists

A consumer pins the version in **two** places:

```yaml
uses: IamRitz/ssd-security-framework/.github/workflows/_source-security.yml@v1
with:
  toolkit_ref: v1     # must match the @v1 above
```

This is a genuine wart, not a design preference. A reusable workflow **cannot
read its own ref**: `job_workflow_ref` / `job_workflow_sha` exist only as OIDC
token claims, and the `github.workflow_ref` / `github.workflow_sha` expression
contexts refer to the *caller's* workflow, not the reusable one. There is no
expression that yields "the ref I was called at", so the ref the workflow uses
to fetch its own scripts has to be stated.

Two things contain the consequences:

1. **A major-version assertion.** Every reusable workflow declares the toolkit
   major it was written against and checks the checked-out `VERSION` file. A
   `v2` toolkit loaded by a `v1` workflow fails the job loudly rather than
   running mismatched scripts against a policy it does not understand.
2. **An empty `toolkit_ref` is refused.** It would otherwise resolve to this
   repository's default branch — an unpinned, moving dependency sitting inside a
   security control.

What the assertion does *not* catch is a mismatch **within** a major: `@v1.2.0`
with `toolkit_ref: v1.0.0` loads older scripts under a newer workflow and passes
the major check. Within a major that combination is contract-compatible by
construction, so it degrades to "older bug fixes" rather than breakage — but
keep the two in sync, and prefer `v1` in both for the common case.

## Releasing

0. **Resolve every open item in [release-blockers.md](release-blockers.md)** —
   `node --test` must report `# todo 0`. A failing TODO is a blocker, not noise.
1. Land the change on `main` with tests green (`node --test` plus
   `tools/verify-consumer-isolation.sh`, and `node tools/render-source-scan.mjs --check`).
2. Update `VERSION` if the major changes.
3. Tag the immutable release: `git tag v1.1.0 && git push origin v1.1.0`.
4. Move the major tag: `git tag -f v1 v1.1.0 && git push -f origin v1`.

Step 4 is what makes the fix propagate. It is also the step that can break every
consumer at once, which is why step 1 is not optional.

## Upgrading a consumer

Consumers on `v1` need do nothing for patch and minor releases.

For a major:

1. Change both the `uses:` ref and `toolkit_ref` to `v2` in a PR.
2. Set `gate_mode: log-only` for that PR if the major changed policy defaults,
   so you see the new verdicts before they block anyone.
3. Read the `v2` release notes for renamed or removed inputs.
4. Return to `enforce`.
