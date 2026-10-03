# GitHub API fixtures for `ssd-onboard github`

Two kinds, distinguished by file name. Every file holds only the fields the
tests and the code under test decide from. No token, header or secret value is
recorded.

## `live-*.json` — captured from the live API (read-only)

Captured on 2026-10-03 with `gh api --method GET` (API version 2022-11-28)
against `IamRitz/ssd-security-framework`, plus the public app endpoint
`GET /apps/github-actions`. Only GET requests were made; nothing was changed.
Error bodies are what `gh` prints on stdout for a non-2xx answer (`status` is a
string); `gh` also prints `gh: <message> (HTTP <status>)` on stderr.

| File | Endpoint | Observed |
| --- | --- | --- |
| `live-repository.json` | `repos/{o}/{r}` | `full_name`, numeric `id`, `default_branch`, `archived`, `permissions` (booleans) |
| `live-branch-unprotected.json` | `repos/{o}/{r}/branches/main` | `protected: false`; `protection.required_status_checks.checks` is a list of `{context, app_id}` |
| `live-protection-not-protected.json` | `repos/{o}/{r}/branches/main/protection` | HTTP 404 `Branch not protected` for an unprotected branch, even to an admin |
| `live-rules-branch-empty.json` | `repos/{o}/{r}/rules/branches/main` | `[]` when no ruleset applies |
| `live-rulesets-empty.json` | `repos/{o}/{r}/rulesets?includes_parents=true` | `[]` when there are none |
| `live-secrets-empty.json` | `repos/{o}/{r}/actions/secrets` | `{total_count, secrets: []}` — names/timestamps only, never values |
| `live-codeowners-errors-no-file.json` | `repos/{o}/{r}/codeowners/errors?ref=main` | HTTP 404 when the branch has no CODEOWNERS file |
| `live-contents-not-found.json` | `repos/{o}/{r}/contents/<CODEOWNERS path>?ref=main` | HTTP 404 for each absent location |
| `live-actions-app.json` | `apps/github-actions` | `id: 15368`, `slug: github-actions`, `owner.login: github` |
| `live-check-run-app.json` | `repos/{o}/{r}/commits/{sha}/check-runs` | a check run created by Actions carries `app.id: 15368` |

## `doc-*.json` — GitHub's documented response schema

The live repository has no ruleset, no classic protection and no CODEOWNERS,
and creating them was out of scope (read-only capture only). These follow the
published REST schema (API version 2022-11-28) for the same endpoints:
ruleset detail (`bypass_actors`, `current_user_can_bypass`, `conditions`,
`rules`), rules for a branch (`ruleset_id`, `ruleset_source_type`,
`ruleset_source`, `parameters`), full classic protection (`enforce_admins`,
`required_pull_request_reviews`, `bypass_pull_request_allowances`),
CODEOWNERS contents and parse errors, and secret metadata. `bypass_actors`
is returned only to a caller allowed to edit the ruleset; the code treats its
absence as UNKNOWN, never as empty.
