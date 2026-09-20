# Repro: reusable-workflow permissions are validated statically

Minimal reproduction for the unresolved limitation in
[onboarding-architecture.md § B.9](../../onboarding-architecture.md#b9-resolved-oidc-least-privilege-for-callers-without-break-glass).

`_reusable.yml` has one job that requests `id-token: write` and **never runs**
(`if: ${{ inputs.enabled }}` with `enabled: false`). `caller.yml` grants the
calling job no `id-token` permission.

Expected, per GitHub's static permission validation (community discussions
[#155062](https://github.com/orgs/community/discussions/155062) and
[#121112](https://github.com/orgs/community/discussions/121112)): the run fails to
start with

```
The nested job 'needs-oidc' is requesting 'id-token: write', but is only allowed 'id-token: none'.
```

even though that job would be skipped. Uncommenting `id-token: write` in
`caller.yml` makes it start. The same thing happens to a consumer calling
`_source-security.yml` without break-glass: the `source-gate` job declares
`id-token: write` (for the break-glass OIDC step only), so every caller must
grant it.

To run it: copy both files into `.github/workflows/` of a scratch repository
(adjust the `uses:` path) and dispatch `caller.yml`. It is not wired into this
repository's CI, because only GitHub's runner validation reproduces it.
