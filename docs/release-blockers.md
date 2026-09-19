# Release blockers

Items that MUST be resolved before the moving `v1` tag is updated, and before
the framework is handed to DevOps. Each has a `todo` test that runs and reports
as a failing TODO in `node --test` output until it is fixed; when it is fixed,
the test passes and its `todo` marker must be removed so it guards the fix.

## RB-1 — `examples/container-ecr/deploy.yml` hard-codes break-glass as passed

**Status:** open. Found during the break-glass OIDC boundary refactor.

The delivery example still calls `_source-security.yml` (the v1 in-job path) and
feeds conformance:

```json
"break-glass": {"status": "pass", "evidence": "lambda transport configured for this repo"}
```

That is a fabricated result: a configuration claim, not an observed decision.
The file deliberately stays on the **v1 compatibility path**: it does not set
`strict_break_glass_evidence`, so conformance still accepts the status-only
record (as v1 always did) and prints a deprecation warning. It is therefore not
broken — but it is not correct either: it reports a pass it has not earned, and
a consumer copying it inherits that. See
[workflow-contracts.md](workflow-contracts.md#break-glass-evidence-and-proving-an-override).

**Fix (separate, delivery-scoped change):** move the delivery example to
`_source-scan.yml` + `_break-glass-lambda.yml` + `final-gate.mjs`, exactly as
`examples/container-ecr/security.yml` does, set `strict_break_glass_evidence:
true`, and feed conformance the structured `break-glass` record. Out of scope for the OIDC boundary patch, which does not
change delivery.

**Guard:** `test/break-glass-oidc-boundary.test.js` —
"RELEASE BLOCKER RB-1: examples/container-ecr/deploy.yml feeds structured break-glass evidence".
