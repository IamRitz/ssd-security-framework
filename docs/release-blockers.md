# Release blockers

Items that MUST be resolved before the moving `v1` tag is updated, and before
the framework is handed to DevOps. Each has a `todo` test that runs and reports
as a failing TODO in `node --test` output until it is fixed; when it is fixed,
the test passes and its `todo` marker must be removed so it guards the fix.

## RB-1 — `examples/container-ecr/deploy.yml` hard-codes break-glass as passed

**Status:** resolved. Found during the break-glass OIDC boundary refactor; fixed
on the same branch by migrating the delivery example to the split architecture.

The delivery example used to call `_source-security.yml` (the v1 in-job path),
grant that job `id-token: write`, and feed conformance:

```json
"break-glass": {"status": "pass", "evidence": "lambda transport configured for this repo"}
```

That was a fabricated result: a configuration claim, not an observed decision. It
was not *broken* — the file stayed on the v1 compatibility path, so conformance
accepted the status-only record and printed a deprecation warning — but it
reported a pass it had not earned, and a consumer copying it inherited that.
See [workflow-contracts.md](workflow-contracts.md#break-glass-evidence-and-proving-an-override).

**Fix (applied):** `deploy.yml` now calls `_source-scan.yml` with no `id-token`,
delegates an eligible enforced BLOCK to a dedicated `_break-glass-lambda.yml`
job (the only job in the source path holding `id-token: write`), and adds a local
aggregate `security-gate` job that runs `security/scripts/final-gate.mjs` over
both workflows' outputs. That job — not the raw `source-security` result — is the
authorization boundary every delivery stage depends on, so an eligible BLOCK with
a verified approval can ship while an unapproved BLOCK, a scanner crash or an
integrity failure cannot. Conformance sets `strict_break_glass_evidence: true`
and is fed the structured, observed `break-glass` record; the source-gate
`override` claim comes from the aggregate gate's own output. `image-security`
remains an independent required gate, and the build/scan/push/gate/deploy digest
chain is unchanged.

**Guard:** `test/break-glass-oidc-boundary.test.js` — describe block
"RB-1: the delivery example is on the split break-glass architecture" (the `todo`
marker is removed, so it now guards the fix rather than reporting the blocker).
