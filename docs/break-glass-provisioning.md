# Break-glass provisioning (Phase 3C)

`ssd-onboard` provisions the two **shared** break-glass stacks with reviewed
CloudFormation, through the same `aws plan` → `aws apply` → `aws verify` path as
the Phase 2 delivery stacks:

| Stack | Environment tag | Holds |
| --- | --- | --- |
| `ssd-break-glass-production` | `ssd:environment=production` | production broker state |
| `ssd-break-glass-synthetic` | `ssd:environment=synthetic` | synthetic (demo/test) broker state |

The broker code and its runtime contract are unchanged: see
[break-glass-setup.md](break-glass-setup.md) for what the broker does, and
[onboarding-architecture.md § Part E](onboarding-architecture.md#part-e--phase-3-break-glass-provisioning)
for the design. This page covers only what 3C provisions and how.

> **Merge order.** The interaction function is provisioned for the Phase 3B
> contract (PR #17): it gets `BREAK_GLASS_ENVIRONMENT` and `ssm:GetParameter` on
> `/ssd/break-glass/<environment>/approvers/*`, and **no** approver map in its
> environment. Running the pre-3B broker code there authorizes nobody, which
> fails closed. Phase 3C merges only after PR #17.

## What each stack holds

All resource names are derived from the environment. None is configured, so
production and synthetic differ in every runtime and security-state resource
by construction. The plan, the template renderer and the operator config
loader also each refuse a pair that would coincide.

| Resource | Name (`<env>` = production or synthetic) | Notes |
| --- | --- | --- |
| DynamoDB table | `ssd-break-glass-<env>-requests` | key `requestId` (S) only; on-demand; **TTL enabled on `ttl`**; point-in-time recovery; deletion protection |
| CI broker | `ssd-break-glass-<env>-ci` | **no Function URL, no resource policy**: reachable only through `lambda:InvokeFunction` by IAM principals |
| Interaction function | `ssd-break-glass-<env>-interactions` | the one public surface: a Function URL with AuthType `NONE`, authenticated by the Slack HMAC signature |
| Function URL permissions | (on the interaction function) | exactly `lambda:InvokeFunctionUrl` (FunctionUrlAuthType `NONE`) and `lambda:InvokeFunction` (**InvokedViaFunctionUrl `true`**) |
| Async follow-up config | (on the interaction function) | 0 retries, 900 s maximum age: a retry could post a second audit comment |
| Execution roles | `ssd-break-glass-<env>-ci-execution`, `ssd-break-glass-<env>-interactions-execution` | trust: `lambda.amazonaws.com` only |
| Secrets (containers) | `ssd/break-glass/<env>/{slack-bot-token,slack-signing-secret,github-token}` | created **empty** (below) |
| Log groups | `/aws/lambda/<function>` | 90-day retention; created by the stack, so no role needs `logs:CreateLogGroup` |

Pinned runtime inputs: `nodejs24.x`, `arm64`, 256 MB, 20 s, handlers
`broker/lambda/index.ciHandler` and `broker/lambda/index.interactionsHandler`.
There is no VPC, because the functions reach Slack, the GitHub API and GitHub's
JWKS over the internet.

### Reserved concurrency: 5 on the interaction function, both environments

The interaction function's Function URL is public, and the Slack signature is
checked **inside** the invocation. Unauthenticated traffic therefore consumes
Lambda concurrency before it is rejected. The stack gives the interaction
function `ReservedConcurrentExecutions: 5`, which caps what that traffic can
take. Requests over the cap are throttled before the function runs, so the CI
broker and every other function in the account keep their concurrency.

**Sizing.** One pool serves two kinds of execution:

| | What runs | Legitimate peak |
| --- | --- | --- |
| synchronous | Slack's POST: verify, authorize, claim, finalize, ack (< 3 s) | 2 (two approvers clicking the same request) |
| asynchronous | the follow-up `enqueueSelf` sends as an `Event` self-invocation: Slack message update and audit comment | 2 (one per POST) |

That is a peak of 4, plus 1 for a cold start (Secrets Manager reads) or the
inline fallback that runs when enqueue fails, which makes 5. The POST does not
wait for its follow-up, so a cap can never deadlock the two. Synthetic gets the
same 5, because the Phase 3E concurrent-claim race test exercises exactly that
peak.

**Under a flood:**
- **Clicks.** Legitimate clicks are throttled too. Break-glass is then
  unavailable and the BLOCK stands, which is fail closed.
- **Follow-ups.** Throttled follow-ups go back on Lambda's async queue and are
  retried until the configured `MaximumEventAgeInSeconds` (900 s).
- **Longer floods.** A flood that lasts longer than that drops them. The
  decision is already final in DynamoDB, but its Slack update and audit comment
  are lost.

**Account precondition.** Lambda keeps at least 100 units of account
concurrency unreserved. `aws plan` reads `lambda get-account-settings` and
blocks (`concurrency-quota`) when the reservation would leave less, so the
public function is never deployed without its cap. A new account with a
concurrency limit of 10 needs a quota increase first.

**CI broker.** It has no reservation: it has no public surface (IAM
`lambda:InvokeFunction` only), so `bg.ci-concurrency` is an advisory WARN.
`bg.interactions-concurrency` is **required**: absent, or anything other than
5, FAILs.

Every resource carries `DeletionPolicy: Retain`, as all ssd-onboard resources do.
A replacement or removal is still classified and counted by the plan, and
`aws apply` needs `--allow-destructive <n>` for it.

Not in these stacks: the per-repository invoker roles and approver parameters
(Phase 3D), the reviewed-SHA policy (3D), and the synthetic workflow contract
(3E). See [Phase sequence and gates](#phase-sequence-and-gates).

## IAM: exactly what the broker calls

| Role | Action | Resource |
| --- | --- | --- |
| CI execution | `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem` | its own table ARN |
| | `secretsmanager:GetSecretValue` | its own `slack-bot-token-??????` |
| | `logs:CreateLogStream`, `logs:PutLogEvents` | `log-group:/aws/lambda/ssd-break-glass-<env>-ci:*` |
| Interaction execution | `dynamodb:GetItem`, `UpdateItem` (no Put, no Delete) | its own table ARN |
| | `secretsmanager:GetSecretValue` | its own three secrets (`-??????` each) |
| | `lambda:InvokeFunction` | its own function ARN (the async follow-up) |
| | `ssm:GetParameter` | `parameter/ssd/break-glass/<env>/approvers/*` (Phase 3B) |
| | `logs:CreateLogStream`, `logs:PutLogEvents` | its own log group `:*` |

`dynamodb:PutItem` on the CI role covers both the pending request and the
one-shot OIDC replay record (`consumeTokenId`, key `oidc-jti:<sha256>`).

No grant uses Action `*` or Resource `*`, and none needs one. Encryption uses
the AWS-owned DynamoDB key and the account's `aws/secretsmanager` key, so no
`kms:` action is needed. Only three wildcard forms appear, and each is checked
for exactly:

- **`<secret name>-??????`**: Secrets Manager appends `-` plus six random
  characters to the ARN. Six `?` match exactly that suffix and nothing longer.
- **`log-group:<own group>:*`**: the log streams Lambda creates in the
  function's own group.
- **`…/approvers/*`**: one parameter per `repository_id`. Onboarding a
  repository adds a parameter, never a policy change.

## Secrets: containers only

`AWS::SecretsManager::Secret` is rendered with neither `SecretString` nor
`GenerateSecretString`. The CloudFormation reference states for both properties:
"If you omit both `GenerateSecretString` and `SecretString`, you create an empty
secret." No value appears in the operator config, the template, the change set,
the plan directory, argv or logs. `aws verify` reads secret **metadata** only
(`describe-secret`) and reports an empty secret as a WARN. Until the values are
put, the broker cannot start, so it fails closed.

After `aws apply`, put each value out of band, from stdin and never from argv:

```
aws secretsmanager put-secret-value \
  --secret-id ssd/break-glass/<env>/slack-bot-token \
  --secret-string file:///dev/stdin
```

Repeat for `slack-signing-secret` and `github-token`. Each environment has its
**own** Slack app; the synthetic stack never holds the production app's token
or signing secret. Then set that Slack app's Interactivity Request URL to the
interaction function's Function URL (`aws lambda get-function-url-config`).

## The Lambda artifact: a published, immutable object version

`aws plan` and `aws apply` never build or upload code. The plan/apply invariant
is unchanged: plan creates a reviewed change set, and apply executes exactly that
change set. The operator config names an **already-published** artifact:

| Field | Requirement |
| --- | --- |
| `bucket` | private: all four public-access-block settings on, no public bucket policy; versioning **Enabled**; in the stack's region |
| `key` | the object key |
| `versionId` | an S3 object version (never `null`); the template pins `S3ObjectVersion`, so a later upload to the same key changes nothing deployed |
| `sha256` | 64-hex SHA-256 of the `.zip` bytes, exactly as `sha256sum` prints it |

The zip's root holds `broker/`, as `git archive --format=zip <commit> broker/`
lays it out. The broker has no dependencies to bundle: the Lambda Node.js
runtime provides the AWS SDK v3.

**The configured `sha256` is never trusted on its own.** A break-glass change
set is created only if all of these hold:

- the object version exists;
- the bucket is private and versioned;
- S3 exposes a **full-object** SHA-256 for that version (`ChecksumType
  FULL_OBJECT`);
- that SHA-256 equals `sha256`.

No checksum, a `COMPOSITE` (multipart) checksum, or no checksum type each block
the plan. SHA-256 is full-object only for a single-part upload, so publish the
bundle with one `PutObject` and `--checksum-algorithm SHA256`. S3's
`ChecksumSHA256` and Lambda's `CodeSha256` are both base64 of the raw digest.

After deployment, `aws verify` compares the live `CodeSha256` with the same
digest. That is a second, independent check of what Lambda actually loaded.

**`CodeSha256`.** Lambda reports `CodeSha256` as the standard, padded **base64
of the raw SHA-256 digest of the .zip bytes**, not hex. The Terraform AWS
provider copies the API's `CodeSha256` into `code_sha256`, which it documents as
"the Base64 encoded SHA-256 hash of the `.zip` file". Every `CodeSha256` sample
in the AWS CLI examples is 44 characters, which is base64 of 32 bytes.
`aws verify` therefore compares the live value with
`base64(hex-decode(sha256))`, exactly.

**Publishing** a deterministic bundle is a separate prerequisite. It is not part
of 3C and has no ssd-onboard command yet. A follow-up will standardise it: fixed
entry order and timestamps, built from a reviewed framework commit, uploaded in
one `PutObject` with `--checksum-algorithm SHA256`.

## The operator configuration

Identifiers only. It is **not** `.ssd/onboarding.yml`: Phase 1 never reads or
writes it, and it is always named explicitly with `--operator-config`. Both
environments are required, so separation is checked as a pair every time. They
may share the artifact but never a Slack channel. A credential-shaped value or
an unknown key refuses the whole file.

```yaml
schemaVersion: "1"
framework:
  repository: IamRitz/ssd-security-framework
  ref: <40-hex commit>          # aws plan must run from this checkout
aws:
  accountId: "123456789012"
  region: us-east-1
environments:
  production:
    slackChannelId: C0123456789
    artifact:
      bucket: ssd-break-glass-artifacts
      key: broker/ssd-broker-<commit>.zip
      versionId: <S3 version id>
      sha256: <64 hex>
  synthetic:
    slackChannelId: C0987654321
    artifact: { … }             # may be the same artifact
```

## Commands

```
ssd-onboard aws plan   --scope break-glass --environment production --operator-config break-glass.yml
ssd-onboard aws apply  --plan-id <id> --account <id> --region <r> --operator-config break-glass.yml
ssd-onboard aws verify --scope break-glass --environment production --operator-config break-glass.yml
```

`--repo <dir>` (default: the current directory) is where `.ssd/aws-plans/` is
written. `.ssd/onboarding.yml` is not needed. A break-glass plan is applied only
with its operator config, which must be unchanged since the plan. A delivery
plan is never applied with one.

### `aws plan --scope break-glass`

The steps run in order, and each one blocks the next:

1. The framework checkout is bound to `framework.ref`.
2. The region is resolved.
3. The caller is the configured account and not root.
4. The stack is absent, an ssd-onboard placeholder, or a settled stack tagged
   for **this** environment.
5. Every named resource is absent or a physical resource of exactly this stack.
   A resource that merely has the name blocks. That includes one owned by the
   **other** environment's stack, which is never adopted.
6. The artifact checks above pass.
7. The trust and permission diffs of both execution roles are recorded. An
   unmanaged policy attached to an owned role blocks.
8. One unexecuted change set is created.

Its allowlist is the Phase 2 planning table, with change-set calls confined to
the two break-glass stacks, plus break-glass metadata reads. It contains no
`put-object`, `put-secret-value`, `get-secret-value` or `get-function`. Doctor,
the delivery plan and the delivery verify keep exactly their Phase 2 allowlists.

### `aws verify --scope break-glass`

The run is read-only. Each fact is its own check:

| Check | Proves |
| --- | --- |
| `bg.stack` | ssd-onboard's stack, tagged for this environment, holding exactly the expected resources under the expected names |
| `bg.separation` | no identifier shared with the other environment; the live functions reference only this environment's table, secrets, channel and roles |
| `bg.table`, `bg.table-ttl` | key schema, billing, deletion protection, PITR; **TTL `ENABLED` on exactly `ttl`** |
| `bg.<fn>-function`, `bg.<fn>-code` | own role, pinned runtime/handler, no VPC or layers, exact environment; **`CodeSha256` = the configured artifact** |
| `bg.ci-exposure` | the CI broker has **no** Function URL and **no** resource policy |
| `bg.interactions-exposure` | one Function URL (`NONE`) and exactly the two URL-scoped public statements. A public `InvokeFunction` without the via-URL condition would deliver a non-URL event, which the handler trusts as its own follow-up. |
| `bg.interactions-async` | 0 retries |
| `bg.interactions-concurrency` | **required**: reserved concurrency exactly 5 (FAIL when absent or different) |
| `bg.ci-concurrency` | advisory WARN when no cap is set (IAM-only function) |
| `bg.secrets` | each secret is this environment's (name, ARN, tag), not deleted; WARN when empty |
| `bg.artifact` | the object version is in a private, versioned bucket, and S3's full-object SHA-256 equals `sha256` |
| `bg.<role>-role`, `bg.<role>-policy-document` | Lambda-only trust; exactly its one inline policy; no wildcard beyond the three documented forms |
| `bg.<role>-required-access` | simulated ALLOW, including **`dynamodb:PutItem` on its own table** for the CI role |
| `bg.<role>-negative-access` | simulated DENY on the other environment's table, secrets, approvers and functions; no Put/Delete for the interaction role; no Scan/Query/DeleteTable/UpdateTimeToLive, PassRole, PutSecretValue or UpdateFunctionCode |

Effective access comes from `iam simulate-principal-policy`, as in Phase 2D. It
does not evaluate resource, session or VPC endpoint policies.

## Phase sequence and gates

Each phase merges once the checks it can satisfy on its own have passed.
Production use waits for all of them
([architecture E.2](onboarding-architecture.md#e2-concrete-defect-to-fix-first-caller-asserted-repository):
the hardened broker is not put into production use until the carried-forward
items land).

| Phase | Delivers | Merge gate |
| --- | --- | --- |
| **3C** (this page) | the shared production and synthetic stacks: template, plan, apply, verify | live validation of the shared infrastructure on the **synthetic** stack ([below](#phase-3c-pre-merge-gate-met-on-the-synthetic-stack)) |
| **3D** | per-repository invoker roles; approver SSM parameters `/ssd/break-glass/<environment>/approvers/<repository_id>`; the reviewed/allowed framework-SHA policy | the per-invoker-role checks of [architecture E.7](onboarding-architecture.md#e7-verification) that apply, against the synthetic stack |
| **3E** | the separate synthetic workflow contract; the ported `verify-live` suite | the negative, race and timeout suite, against the synthetic stack only |
| **Pre-production** | production in service | [below](#pre-production-gate-after-3d-and-3e) |

The 3E suite is not a 3C merge gate. Its approver, race and timeout cases need
a request filed with a verified repository identity through a per-repository
invoker role, and an approver parameter to authorize against. Both are 3D, so
gating 3C on 3E would block 3C on its own successors.

### Phase 3C pre-merge gate: met on the synthetic stack

Observed live against `ssd-break-glass-synthetic`, deployed from the reviewed,
published artifact and verified at framework commit `1feaad3`:

1. **`aws verify --scope break-glass`: 25 PASS, 2 WARN, 0 NOT VERIFIED,
   0 FAIL.** This is the live proof of the CI role's `dynamodb:PutItem` on its
   own table (and its denial on the other environment's), TTL `ENABLED` on
   `ttl`, both roles' required and negative access, and production separation.
   Both warnings are expected:
   - `bg.ci-concurrency`: the CI broker has no reservation (advisory, above);
   - `bg.secrets`: all three secret containers are empty, as created.
2. **Live `CodeSha256` comparison.** `bg.ci-code` and `bg.interactions-code`
   pass: both functions report `base64(hex-decode(sha256))` of the configured
   artifact.
3. **Empty secrets as created.** After the first apply, and before any value
   was put, `describe-secret` showed each CloudFormation-created secret with no
   versions and no `AWSCURRENT`.
4. **The live Function URL resource-policy shape.** `lambda get-policy` on the
   interaction function returned exactly the two statements CloudFormation
   created, `lambda:InvokeFunctionUrl` (FunctionUrlAuthType `NONE`) and
   `lambda:InvokeFunction` (InvokedViaFunctionUrl `true`), and
   `bg.interactions-exposure` recognises them.

Phase 3C does **not** deploy the production stack. Its template is reviewed and
tested against recorded AWS behaviour only, and its live proof is the
pre-production gate.

### Pre-production gate (after 3D and 3E)

**The production stack is not production-ready** until, after 3D and 3E have
landed:

1. **Production deployed and verified on the final reviewed artifact.** Deploy
   `ssd-break-glass-production` from the artifact that carries every
   merged broker change, and pass `aws verify --scope break-glass` against the
   production and synthetic stacks. That includes the live `CodeSha256`
   comparison, empty secrets as created, and the Function URL resource-policy
   shape, now on production. Verify fails closed if the policy shape differs;
   adjust the expected shape only from an observation.
2. **Production secrets populated** out of band (`put-secret-value
   --secret-string file:///dev/stdin`), never in config, templates, change
   sets, plans, argv or logs.
3. **The production Slack Request URL configured**: the production Slack app's
   Interactivity Request URL set to the production interaction function's
   Function URL. It must be live when saved
   ([onboarding.md § 3.3](onboarding.md#33-the-slack-app-org)).
4. **Repository approver parameters onboarded** (Phase 3D), one per repository,
   before its first request. Until then nobody is authorized for it.

## Residual limitations

- **Quota headroom is not always proven at plan time.** When `lambda
  get-account-settings` cannot be read, `aws plan` reports
  `concurrency-quota-unverified` (NOT VERIFIED) and still creates the change
  set. This is a deliberate trade-off: planning stays available without that
  read permission. The cost is that a reservation that does not fit fails at
  apply and CloudFormation rolls back. Insufficient headroom that *is* read
  always blocks.
- A flood of unauthenticated requests longer than 900 s drops throttled
  follow-ups, so a final decision may then lack its Slack update and audit
  comment. There is no dead-letter queue or failure destination in 3C.
- A retained `AWS::Lambda::Permission` that a future change replaces leaves its
  old statement behind; verify then fails `bg.interactions-exposure` until the
  extra statement is removed.
- Artifact publishing is a prerequisite with no ssd-onboard command yet.
- The interaction function's `ssm:GetParameter` grant serves the Phase 3B
  approver lookup (PR #17); on pre-3B broker code it has no caller. 3C merges
  only after #17.
