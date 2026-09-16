# Break-glass reference

[`onboarding.md`](onboarding.md) has the setup checklist. This is the reference:
what break-glass may and may not override, how the CI side stays fail-closed,
and what a repo without an approval channel gets.

## What it is

A narrow, audited path for a human to approve a BLOCK that policy has already
judged **eligible**. It is not a bypass switch, and the approver does not choose
what is overridable — the policy does, before any human is asked.

| Eligible | Never eligible |
| --- | --- |
| a new high/critical SAST finding | a verified secret |
| a fixable high/critical dependency finding | a known-malicious (`MAL-`) package |
| | a report-integrity failure |

A **mixed** BLOCK containing any hard block is not eligible. Dependency findings
with no fix available are not eligible either — the gate already treats them as
EXCEPTION, so there is nothing to override.

Report-integrity failures are never overridable for a specific reason: an
integrity failure means a scanner could not interpret its input, so the findings
list is **unknown**, not clean. Approving "no findings" that were never actually
computed is approving nothing at all.

## The CI side is fail-closed by construction

The order of operations matters more than any individual check:

1. The gate produces a verdict and writes `breakGlass.eligible` into its report.
2. **Eligibility is confirmed before any approval credential is loaded.** The
   `--check-only` step runs first, with no role assumed and no secret in the
   environment. A hard block fails there and never reaches the approval channel.
3. Only then is the invoker role assumed (or the shared secret read).
4. The request is sent, and CI polls for a **verified** decision.

Only an `approved` decision lets the gate job succeed. Denied, expired,
malformed, unreachable, and timed-out all remain failed. There is no path where
an absent or unparseable answer becomes an approval.

The framework's own tests assert step 2 precedes step 3, because the ordering is
the control and reordering it would not fail anything at runtime.

## Transports

| | `lambda` (recommended) | `http` (legacy) |
| --- | --- | --- |
| Auth | GitHub OIDC → scoped invoker role | HMAC shared secret |
| Repository secret | **none** | `break_glass_shared_secret` |
| Public surface | none | a webhook endpoint |
| Race safety | DynamoDB conditional write | depends on the host |

The `lambda` transport needs no repository secret at all, which removes the
whole class of "the secret leaked / the secret rotated and CI broke" problems.
Prefer it. The `http` transport remains for rollback and for existing consumers.

## Synthetic runs are isolated by construction

`synthetic_block_fixture` injects a **fabricated** eligible BLOCK so the approval
path can be demonstrated without real vulnerable code. That fabricated finding
must never reach the real broker, where it would page real approvers and record a
real decision against a finding that does not exist.

Isolation is required per transport, and the run fails before anything is
assumed or invoked if it is missing:

| Transport | Required for a synthetic run |
| --- | --- |
| `http` | `break_glass_notify_url` **and** `break_glass_status_url` — explicit dev endpoints |
| `lambda` | `synthetic_break_glass_lambda_function` **and** `synthetic_break_glass_lambda_role_arn`, each **different from** its production counterpart (plus a region) |

Three properties make this safe rather than merely discouraged:

1. **It fails before any credential exists.** The isolation guard runs *before*
   the gate evaluates, and therefore before OIDC role assumption and before any
   broker invocation. The ordering is the control, and the framework's tests
   assert it — a guard that ran after the role was assumed would prove nothing.
2. **Production identifiers cannot be reused.** Passing the production function
   or role ARN as the synthetic one is rejected explicitly. "Isolation" means a
   separate broker, not the same broker under a different label.
3. **Nothing is inferred from a name.** A function called `break-glass-test` is
   not evidence of anything. The framework never pattern-matches on names; it
   requires the identifiers to be supplied and to differ.

The steps that talk to the broker use a **resolved** function and role, never the
raw production inputs, so there is no code path on which a synthetic run reaches
production configuration by omission.

Eligibility is still checked first. A synthetic run of a *hard* block — a
verified secret, a malicious package, a report-integrity failure — fails at the
eligibility step exactly like a real one, before any of the above matters.

## Infrastructure

**Per AWS account**, shared by every repo:

- **Broker Lambda** — receives the request, posts to Slack, serves decision
  status back to CI.
- **Interaction handler Lambda** — receives Slack's signed button clicks,
  verifies them, and claims the decision.
- **DynamoDB table** — pending requests. The `pending → processing →
  approved|denied` transition is a **conditional write**, which is what makes a
  double-click race impossible rather than merely unlikely. Two approvers
  clicking simultaneously produce one decision, not two.
- **Secrets Manager** — the Slack bot token and signing secret.

**Per repository**: a dedicated OIDC invoker role that can invoke *only* the
broker function. Verify the negative case explicitly — assuming that role and
calling the interaction handler, the DynamoDB table, or Secrets Manager must all
return AccessDenied. A role you have only tested positively is not scoped.

## Slack

The bot needs exactly one scope: **`chat:write`**. If you find yourself adding
more, something has gone wrong with the design rather than the permissions.

Three things reliably go wrong:

- **The bot is not in the channel.** `chat.postMessage` returns
  `not_in_channel`. Invite it.
- **The Request URL is saved before the endpoint is live.** Slack sends a
  verification request when you save the Interactivity Request URL and rejects
  it unless it gets a valid signed response. Deploy first, then paste the URL.
- **Socket Mode is on.** It bypasses the signed HTTP POST the design depends on.
  Turn it off.

Slack signs `v0:{timestamp}:{raw_body}` with the signing secret. Verification
happens on the **raw body, before parsing**, and timestamps older than five
minutes are rejected. Invalid signatures get HTTP 401 before any state is
touched.

## Authorization is per repo and fail-closed

```
SLACK_APPROVER_IDS_BY_REPO={"org/repo-a":["U123"],"org/repo-b":["U456","U789"]}
```

- A repo **not present as a key authorizes nobody.** No fallback to a shared
  default list. A repo is not onboarded to break-glass until it has an explicit
  entry.
- **Malformed JSON is treated as an empty map** — nobody authorized for
  anything — logged, never thrown. One bad edit cannot take down approvals for
  every repo at once.
- The repository identity comes from the **stored pending request**, looked up
  by request ID when the click arrives. It is **never** read from the Slack
  interaction payload, which has no notion of a GitHub repository and therefore
  offers nothing to forge. The clicking user is checked against that repo's set
  only.

Changing the map is an environment change and needs the handler restarted.

## A repository with no Slack

**Break-glass is unavailable, and that is a supported, recorded configuration.**

Leave `break_glass_enabled: false` (the default). An eligible BLOCK then behaves
like any other BLOCK: it fails, and the remedy is to fix the finding. The
conformance report marks the control **N/A** with the reason
`break_glass_enabled=false` — not as a gap, and not as an exemption.

Say this out loud during onboarding. "This repo has no override path" is a
legitimate answer. The failure mode to avoid is a team that *believes* it has an
override and finds out during an incident that the repo was never in the
approver map.

## Fork pull requests

GitHub withholds secrets and OIDC tokens from fork PRs entirely, so break-glass
fails closed there regardless of configuration. This is deliberate and should
not be "fixed": the callers use `pull_request`, never
`pull_request_target`, precisely so untrusted fork code never runs with a
writable token or reachable credentials.

## Audit trail

Every decision records the verified approver identity, the timestamp, the
findings, and a digest of the gate result it approved. The gate digest matters:
it binds the approval to **one specific set of findings**, so an approval cannot
be replayed against a later, different BLOCK.
