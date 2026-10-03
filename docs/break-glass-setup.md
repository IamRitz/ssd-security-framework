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

## Where the OIDC permission lives

GitHub checks a called workflow's job permissions **before** any `if:` runs. A
workflow that contains one `id-token: write` job therefore forces **every**
caller to grant OIDC — even a repository with break-glass disabled. So:

| Repository | Calls | `id-token: write` granted to |
| --- | --- | --- |
| no break-glass | `_source-scan.yml` | **nothing** |
| Lambda break-glass (recommended) | `_source-scan.yml` + `_break-glass-lambda.yml` | **only** the `break-glass` job |
| legacy HTTP break-glass | `_source-scan.yml` (HTTP runs in-job) | nothing |
| existing v1 caller | `_source-security.yml` (unchanged) | the source-security job, as before |

`examples/container-ecr/security.yml` is the canonical Lambda caller.

## The CI side is fail-closed by construction

### Lambda break-glass (`_break-glass-lambda.yml`)

The credential-bearing job runs **no consumer code**: it never checks out the
consumer repository, and before the OIDC step it only uses pinned actions and
framework scripts. In order:

1. Download **this run's** `security-gate-results` artifact.
2. Re-derive from that evidence, in framework code: the run it belongs to
   (repository, commit, run id), that it is **the exact gate** the source
   workflow evaluated (SHA-256 equal to the source `gate_digest` output),
   eligibility from the **raw findings** (not from the source workflow's
   `break_glass_eligible` output, which is only a pre-filter), and the broker
   route from the evidence's `synthetic` record.
3. **Only then** assume the invoker role through OIDC.
4. Send the request and poll for a **verified** decision (requestId and gate
   digest must match exactly).
5. Publish `decision_status` and friends; the caller's `security-gate` runs
   `final-gate.mjs`, which requires every fact before reporting an
   **overridden BLOCK**. The source policy verdict stays BLOCK.

The source workflow's normal Slack BLOCK alert is **never** suppressed by
delegation, so a skipped or misconfigured break-glass job cannot lose it.
Approvers may see that alert and the interactive request for the same BLOCK;
that duplicate is deliberate (fail-safe) until something can observe delivery.

Pin the invoker role's trust policy to this workflow's `job_workflow_ref`
(`IamRitz/ssd-security-framework/.github/workflows/_break-glass-lambda.yml@<ref>`),
so only this reviewed job — not an arbitrary job in the consumer repository —
can assume it.

### In-job break-glass (`_source-security.yml`, and HTTP in `_source-scan.yml`)

The order of operations matters more than any individual check:

1. The gate produces a verdict and writes `breakGlass.eligible` into its report.
2. **Eligibility is confirmed before any approval credential is loaded.** The
   `--check-only` step runs first, with no role assumed and no secret in the
   environment. A hard block fails there and never reaches the approval channel.
3. Only then is the invoker role assumed (or the shared secret read).
4. The request is sent, and CI polls for a **verified** decision.

What the developer is told follows the same order, and never skips ahead:
**eligible** (policy) does not mean **enabled** (this repo), which does not mean
a request was **sent**, which does not mean a **decision** exists. An eligible
BLOCK in a repo with break-glass disabled reads "eligible by policy, but not
enabled for this repository", and still gets the normal BLOCK Slack alert. Only
a request the broker actually accepted suppresses that alert, and only a
verified approval is described as an override. See
[workflow-contracts.md § developer feedback](workflow-contracts.md#developer-feedback-every-statement-is-observed-state).

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
| Request identity | **verified GitHub OIDC token** (below) | **caller-asserted** |

The `lambda` transport needs no repository secret at all, which removes the
whole class of "the secret leaked / the secret rotated and CI broke" problems.
Prefer it. The `http` transport remains for rollback and for existing consumers.
It cannot carry a verified identity: in `_source-scan.yml` it runs in a job
that has no OIDC token, and that job stays OIDC-free on purpose. So an `http`
broker trusts the repository its caller names. It is suitable for a single
repository only, and it is never generated.

## Synthetic runs are isolated by construction

**Lambda (`_break-glass-lambda.yml`): the route comes from the evidence.** The
source gate records `synthetic: {active, fixture}` in `security-gate.json`
whenever a fixture is injected (and `active: false` otherwise; a result with
neither is refused). The break-glass workflow has **no** input that turns
synthetic routing on or off. For synthetic evidence it requires
`synthetic_lambda_function` **and** `synthetic_lambda_role_arn`, **and** the
production pair to compare against, and refuses if either synthetic identifier
equals production (an ARN of the production function counts as production).
There is no fallback to production. All of this runs before the OIDC step.

The rest of this section describes the in-job transports.

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

## Who is asking: verified GitHub identity

The broker does not believe the repository, pull request or run named in a
request. Every `notify` and every `status` call carries a GitHub OIDC token
minted for the dedicated audience **`ssd-break-glass`** (separate from the
`sts.amazonaws.com` token the job uses to assume its AWS role), and the broker
verifies it before anything else (`broker/identity/github-oidc.mjs`):

| Check | Required value |
| --- | --- |
| signature | RS256 only, key found by `kid` in GitHub's JWKS at the fixed URL `https://token.actions.githubusercontent.com/.well-known/jwks`; RSA ≥ 2048 bits; header `jku`/`jwk`/`x5u`/`x5c`/`crit` refused |
| `iss` | exactly `https://token.actions.githubusercontent.com` (an enterprise-scoped issuer is refused) |
| `aud` | exactly `ssd-break-glass` |
| `exp` / `iat` / `nbf` | not expired; `iat` at most 300 s old and not in the future; `nbf` (when present) not in the future (30 s skew) |
| `job_workflow_ref` | parsed into repository, path and ref: repository `IamRitz/ssd-security-framework`, path `.github/workflows/_break-glass-lambda.yml` or `.github/workflows/_source-security.yml`, ref a 40-character commit SHA equal to `job_workflow_sha` |
| `event_name` / `ref` | `pull_request` with `ref` = `refs/pull/<N>/merge`; the PR number is `<N>` |
| `jti` | accepted **once** (an atomic conditional write in the request table) |

What the broker then does with it:

- **Identity comes from the token.** The stored request keeps the verified
  `identity` (repository, `repository_id`, PR, commit, run, run attempt,
  `job_workflow_ref`) separately from the display `context`. The payload's
  `context` may still carry `repository`, `pullRequest`, `commitSha`, `runUrl`,
  `ciSystem`, `repositoryId`, `runId`, `runAttempt`, but every supplied value
  must **equal** the token's. A disagreement is a rejection, never a
  correction, and so is any other context field.
- **Approvers are keyed by `repository_id`**, the immutable id, so a renamed
  or re-created repository cannot inherit someone else's approvers.
- **The audit comment** goes to the token's repository and pull request.
- **Status is bound to the filing run.** A `status` call needs its own fresh
  token whose `repository_id`, `run_id` and `run_attempt` equal the request's.
  A request id alone authorizes nothing.
- **Refusals are logged with** the rejection code, any verified ids and what
  the payload claimed, so abuse is investigable. Tokens are never logged,
  stored or echoed.

Replay records are keyed `oidc-jti:<sha256(jti)>` and hold only the action,
`repository_id`, run id, run attempt and token expiry. Their DynamoDB `ttl` is
one hour after the token's `exp`, so a record always outlives the token it
guards. TTL deletion is lazy and happens only after that.

### Request creation order, and what a failure leaves behind

`notify` writes in this order, and nothing before step 2 writes at all:

1. **Check the payload shape and verify the token.** Nothing is written.
2. **Claim the token's `jti`** with a conditional write. This is the first write.
3. **Bind the payload to the token.** A disagreement is refused, and the token
   is already spent. This order is **intentional**: claiming first means no
   path, valid or not, can use a token twice, and the cost is only that a
   corrected retry mints a fresh token, which every caller can do.
4. **Store the pending request** under a fresh UUID.
5. **Post the Slack approval message**, then record its reference. If that
   fails, the request is deleted and the call returns 502.

The client never retries `notify`. A retry means either a resend of the same
event (for example, the AWS CLI retrying after a lost response) or a new step or
job attempt with a new token.

| Failure at | What remains | Retry with the same event | Retry with a new token |
| --- | --- | --- | --- |
| 1 | nothing | refused again | normal |
| 3 | spent token | `token_replayed` | normal, if the payload is corrected |
| 4 (storage) | spent token, no request, nobody paged | `token_replayed` | exactly one request |
| 5 (Slack) | spent token; request rolled back | `token_replayed` | exactly one request and one message |
| 5, rollback also fails | an orphan pending request with **no** Slack message | `token_replayed` | one request with a message, plus the orphan, which nobody can click and which expires at `expiresAt` |
| after 5, response lost | one complete request | `token_replayed`: **no duplicate** | not attempted by the client (the step fails, and the BLOCK stands) |

Two cases leave a stale Slack message, though never a second approvable
request for the same run:

- **Slack posted, but its response was lost.** The request is rolled back, and
  a click on the message gets "unknown request".
- **The broker delivered, but CI never saw the response, and someone re-runs
  the job.** The new attempt files its own request. The earlier message stays
  approvable, but its status can only be read by the earlier, finished attempt,
  so approving it changes no gate (it does post an audit comment).

### Rollout order, and what fails closed

1. **Client first.** Framework callers at a commit that includes this change
   send the token. The pre-hardening broker ignores the extra field, so this
   step changes nothing on its own.
2. **Broker second.** Once the hardened broker is deployed (Phase 3C provisions
   it), it refuses every request that does not prove its identity:
   - a caller pinned to an **older framework commit** sends no token, so its
     request is refused (`identity_rejected: token_missing`). The request is not
     delivered and **the BLOCK stands**;
   - a caller that pins the framework by **tag or branch** (`@v1`) yields a
     `job_workflow_ref` that is not a SHA and is refused. Generated callers
     always pin an exact SHA;
   - a request from **`workflow_dispatch`, `push`, `schedule` or
     `pull_request_target`** is refused. That includes a manually dispatched
     synthetic demo: a non-PR synthetic route needs its own, explicitly
     separate contract (Phase 3E);
   - **pending requests filed before the hardening** have no stored identity.
     They match no status caller and authorize no approver, so they simply
     expire. That is fail-closed by design.
3. **Re-key the approver map** at the same time (below). Until then, nobody is
   authorized.

## Authorization is per repository and fail-closed

```
SLACK_APPROVER_IDS_BY_REPOSITORY_ID={"1001":["U123"],"1002":["U456","U789"]}
```

Keys are GitHub `repository_id`s (`gh api repos/<owner>/<repo> --jq .id`).

- A repository **not present as a key authorizes nobody.** There is no fallback
  to a shared default list. A repository is not onboarded to break-glass until
  it has an explicit entry.
- **Malformed JSON is treated as an empty map**: nobody is authorized for
  anything. It is logged, never thrown, so one bad edit cannot take down
  approvals for every repository at once.
- A key that is not a repository id is ignored, including an `"owner/repo"` key
  from the pre-hardening `SLACK_APPROVER_IDS_BY_REPO` format. That variable is
  no longer read.
- The repository is the **stored request's verified identity**, looked up by
  request id when the click arrives. It is never read from the Slack interaction
  payload or from the display context. The clicking user is checked against
  that repository's set only.

Changing the map is an environment change and needs the handler restarted.
(Phase 3B moves it to one SSM parameter per repository.)

## A repository with no Slack

**Break-glass is unavailable, and that is a supported, recorded configuration.**

Leave `break_glass_enabled: false` (the default). An eligible BLOCK then behaves
like any other BLOCK: it fails, the normal BLOCK alert is sent, and the remedy is
to fix the finding. Developers are told the finding is eligible by policy but
that break-glass is not enabled here — never that a request was sent. The
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
