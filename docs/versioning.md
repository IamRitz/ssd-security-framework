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

1. Land the change on `main` with tests green (`node --test` plus
   `tools/verify-consumer-isolation.sh`).
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
