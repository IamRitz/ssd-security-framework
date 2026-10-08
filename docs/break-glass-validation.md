# Break-glass end-to-end validation (Phase 3E)

**Status: Phase 3E contract — implementation in progress.** Nothing on this
page has been run live yet. Every live result is recorded in
[§ Evidence](#evidence-to-be-filled) from the run itself, and an empty slot
means "not yet proven". Production is not touched in 3E.

Phase 3C provisioned the shared broker stacks and 3D the governance and
per-repository stacks ([break-glass-repositories.md](break-glass-repositories.md)).
3E proves the whole workflow contract end to end, against the **synthetic**
environment only, and closes one isolation gap the client could not close on
its own (environment binding, below).

## The synthetic live contract

A synthetic run is an ordinary `pull_request` run. There is no
`workflow_dispatch` route, and the broker's production rules (`pull_request`
only, PR number from the verified ref) are not weakened for it.

| Part | Requirement |
| --- | --- |
| Repository | one dedicated synthetic repository, onboarded to **synthetic only** (`environments.synthetic` in its repository file; no production stack). It is never a production consumer |
| Trigger | `pull_request` from a branch of that repository (fork pull requests get no OIDC token and fail closed) |
| Caller | the template `examples/synthetic-break-glass/security.yml`: `_source-scan.yml` with `synthetic_block_fixture` set, and a separate `break-glass` job calling `_break-glass-lambda.yml` |
| Identifiers | the synthetic function and invoker role **and** the production pair, each different. Production does not exist yet, so the production pair is the derived names (`ssd-break-glass-production-ci`, `ssd-break-glass-production-invoker-<repository_id>`); they are compared, never invoked |
| Framework commit | admitted in the synthetic governance stack only. A candidate commit not yet on `main` may be admitted there, explicitly; production cannot admit it |
| Secrets | the synthetic stack's three secrets are populated (bot token, signing secret, GitHub token scoped to the synthetic repository). The interaction function reads all three at start-up, so it cannot start without them. Production secrets stay empty |
| Slack | a synthetic Slack app and channel, separate from production |

### Environment binding (broker side)

The client routes synthetic evidence to the synthetic broker and refuses
identifiers equal to production's. Those identifiers are supplied by the
caller, so that comparison alone does not prove which environment the
receiving broker serves: a misconfigured caller could send a synthetic request
to the production broker, or the reverse. This is a misrouting defence, not an
approval control: approvers still decide, and every decision stays bound to
the gate digest. 3E binds the environment on both sides:

1. **The framework derives the environment from validated evidence.** In
   `break-glass-notify.mjs`, from the same gate object whose SHA-256 is the
   request's `gateDigest`: `synthetic.active === true` is `synthetic`,
   `false` is `production`, anything else refuses before any call. In
   `_break-glass-lambda.yml` it must also equal the preflight's resolved
   `route` (a step output of framework code, never a workflow input). No
   workflow input names or sets the environment.
2. **The request carries it** as the top-level `environment` field of the
   Lambda notify payload (`production` or `synthetic`). The legacy HTTP
   payload is unchanged.
3. **The broker compares it with its own `BREAK_GLASS_ENVIRONMENT`** before
   the token is verified or spent. Omitted, malformed or different is refused
   (`403 environment_mismatch`, or `400 invalid request environment`), and
   nothing is written. A broker without a valid environment refuses every
   request.
4. **The stored request records it.** A `status` call and a click act only on
   a stored request whose `environment` is the broker's own; anything else
   (including a request stored before 3E, with none) is refused without a
   state change.
5. **Slack labels it.** A synthetic approval message and its decision update
   say so in their first line.

## Evidence matrix

Live mode: **offline** = in-process only; **AWS** = live AWS, no Slack
credentials; **Slack** = needs the synthetic Slack credentials (clicks are
signed by the driver with the synthetic signing secret, so most need no human).

| | Property | Offline coverage | Live mode | Live procedure | Slot |
| --- | --- | --- | --- | --- | --- |
| A | eligible BLOCK → request → approval → overridden BLOCK | `break-glass-scenarios` A; `broker-lambda` "approves end to end"; final gate and conformance | Slack | fixture PR; approve (signed click, and once by a human) | V-A |
| B | explicit denial → BLOCK stays | scenarios B; `broker-lambda` "denies" | Slack | deny | V-B |
| C | timeout → BLOCK stays | scenarios C; `break-glass-ux` timeout | Slack | `timeout_seconds: 60`, no click | V-C |
| D | invalid or missing broker response → BLOCK stays | `break-glass-ux` malformed / error / transport | AWS | 3D E6 (`502 slack_post_failed`) | 3D E6 |
| E | two approvers click at once → one decision | scenarios E; `broker-lambda` 25 concurrent clicks | Slack | driver `race`: approve and deny at once | V-E |
| F | repeated click after decision → no transition | scenarios F | Slack | driver click after V-E | V-F |
| G | commit revoked before click → refused | scenarios G/H; `broker-oidc-identity` revoke | Slack | governance plan/apply without the commit; click | V-GH |
| H | commit revoked while CI polls → poll fails closed | scenarios G/H | Slack | the same revoke, during the poll | V-GH |
| I | approver removed before click → current list decides | scenarios I | Slack | repository apply without U_A; U_A, then U_B click | V-I |
| J | `[]` approvers → nobody decides | scenarios J | Slack | repository apply with `[]`; click | V-J |
| K | wrong Slack signer or stale timestamp → no state change | `broker-authorize`, `broker-lambda` 401 | Slack (signing secret only) | driver `signature` | V-K |
| L | wrong repository / run / attempt status token → refused | `broker-oidc-identity` status binding | offline only | unreachable live (below) | — |
| M | OIDC token replay → refused | `broker-oidc-identity` replay | offline only | unreachable live (below) | — |
| N | Slack post failure → request rolled back | `broker-lambda`, `broker-oidc-identity` rollback | AWS | 3D E6 | 3D E6 |
| O | lost response / retry → no duplicate | `broker-oidc-identity` "resend refused" | offline only | not reproducible live | — |
| P | synthetic never reaches production | `break-glass-oidc-boundary` isolation; environment binding tests | AWS | repository verify negatives; production broker probe at pre-production | 3D E4 |
| Q | hard blocks stay non-overridable | `break-glass-oidc-boundary` revalidation; `broker-lambda` | offline only | no live hard-block fixture exists | — |
| R | status, decision and gate digest bound exactly | scenarios R; gate digest tests | Slack | from V-A's artifacts | V-A |

**Unreachable live, by design.** L and M need a status call for another run,
or a second use of a token. Only code running inside `_break-glass-lambda.yml`
at an admitted commit can make a call the broker accepts, and that code never
does either. Testing them live would mean admitting an adversarial workflow
commit, which 3E does not do. The broker code is the same code tested offline,
and the live race (E) exercises the same DynamoDB conditional writes. O needs
a response dropped in transit; Q needs a live hard-block finding, which the
fixtures do not provide (they inject eligible BLOCKs only).

## The live driver: `tools/break-glass-live.mjs`

Signs Slack interactions with the synthetic signing secret and sends them to
the synthetic interaction Function URL. It is not part of the broker, never
runs in CI, and never targets production:

- it requires `--environment synthetic` and refuses anything else;
- it reads the Function URL of `ssd-break-glass-synthetic-interactions` from
  AWS and refuses unless `--function-url` equals it;
- it reads the signing secret from stdin only; never from argv, a file name
  or the environment, and never prints or writes it;
- it prints one JSON evidence document per run (outcomes from the broker's
  `x-break-glass-outcome` header, never the secret).

| Scenario | Sends | Expected |
| --- | --- | --- |
| `click` | one signed click as `--user` with `--action` | the broker's outcome |
| `race` | two signed clicks at once (approve as one user, deny as the other) | exactly one `claimed`, the other `duplicate` |
| `repeat` | one signed click on a decided request | `duplicate` |
| `signature` | wrong secret, stale timestamp, tampered body, unsigned; then one valid click | 401 for each forgery, then the valid click proves the request was untouched |

## Live session order

One session, synthetic only, approvers starting as `[U_A, U_B]`:

1. A (once by signed click, once by a human in Slack), B, C, R from A;
2. E then F on one request; K on another;
3. I: apply approvers `[U_B]`, click as U_A, then U_B;
4. J: apply approvers `[]`, click; then restore `[U_A, U_B]`;
5. G and H: file a request, apply the governance stack without the commit
   (the poll fails), click (revoked); re-admit the commit.

Every change goes through `aws plan` and `aws apply`; the bootstrap admin is
not used.

**Human demonstrations retained** even though automated: A (approve in Slack,
green overridden BLOCK), B (deny), E (two people clicking together), G
(`revoked` reply after a revoke), J (`[]`: "not an authorized approver").

## Evidence (to be filled)

> **Nothing below has been run yet.**

| Slot | Evidence | Result |
| --- | --- | --- |
| V-0 | framework commit admitted in synthetic, artifact coordinates, shared-stack update with the 3E broker, the synthetic repository's id and stack | _TBD_ |
| V-A | run URL, request id, Slack message, decision, overridden BLOCK, and R: source `gate_digest` = request = decision = final gate | _TBD_ |
| V-B | run URL, denied, BLOCK stands | _TBD_ |
| V-C | run URL, timeout, BLOCK stands | _TBD_ |
| V-E | driver JSON: one `claimed`, one `duplicate`; one audit comment | _TBD_ |
| V-F | driver JSON: `duplicate`, no change | _TBD_ |
| V-GH | governance plan id; poll refused `framework_sha_not_allowed`; click `revoked`; re-admit plan id | _TBD_ |
| V-I | repository plan id; U_A `unauthorized`, U_B `claimed` | _TBD_ |
| V-J | repository plan id; `unauthorized`; restore plan id | _TBD_ |
| V-K | driver JSON: four 401s, then the valid click | _TBD_ |
| V-ENV | a synthetic request sent to a broker of the other environment is refused `environment_mismatch` (offline proof; live at pre-production) | _TBD_ |
