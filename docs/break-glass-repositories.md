# Break-glass repositories and framework governance (Phase 3D)

**Status: Phase 3D contract — implementation in progress.** This page
specifies Phase 3D; the runtime code, templates and checks that implement it
follow in this pull request, and none of it exists on `main` yet. The live
evidence is recorded in [§ Live validation](#live-validation-synthetic-only)
when that work lands.
Production is not touched in 3D: no production stack is planned, applied or
verified (an `aws plan` already creates a placeholder stack).

Phase 3C provisioned the two shared broker stacks
([break-glass-provisioning.md](break-glass-provisioning.md)). Phase 3D adds
what lets a **repository** use one of them, and what decides which
**framework code** may file a request:

| Stack (`<env>` = production or synthetic) | Holds | One per |
| --- | --- | --- |
| `ssd-break-glass-<env>-governance` | the environment's allowed framework commits | environment |
| `ssd-break-glass-<env>-repo-<repository_id>` | the repository's invoker role and approver parameter | repository and environment |
| `ssd-break-glass-<env>` (3C) | unchanged resources; two read grants and one environment variable added ([below](#changes-to-the-shared-stacks)) | environment |

Every name is derived from the environment and the immutable GitHub
`repository_id`; none is configured. Every resource keeps
`DeletionPolicy: Retain`, so **revoking is always a value change, never a
removal** (below).

## Which framework code may ask: `job_workflow_sha`

The broker trusts a request because reviewed framework code built it: that
code re-derived eligibility from the raw findings, bound the request to its
run and to the exact gate digest, and chose the production or synthetic route
from the evidence. The commit that code came from is therefore the thing to
authorize. Phase 3D makes that commit **`job_workflow_sha`**, the commit of the
credential-bearing reusable workflow as GitHub reports it in the job's OIDC
token, and closes the two ways other code could run under it.

### 1. The workflow runs its own commit, and nothing else

Before 3D, `_break-glass-lambda.yml` checked its scripts out at
`inputs.toolkit_ref`, which the caller chooses. Every `run:` step of a job with
`id-token: write` can mint OIDC tokens, so an admitted workflow commit could
run scripts from any other ref and file requests under the admitted commit's
identity. The workflow now binds itself first. Its **first step**, before any
checkout and before any framework script, is inline shell (`curl`, `jq`,
coreutils on the fixed `ubuntu-latest` runner) that:

1. mints a GitHub OIDC token for the audience `ssd-framework-binding` and masks
   it at once. Nothing accepts that audience: AWS roles require
   `sts.amazonaws.com` and the broker requires `ssd-break-glass`. The token is
   never printed, written to a file or passed on;
2. reads `job_workflow_ref` and `job_workflow_sha` from its payload;
3. requires `job_workflow_sha` to be exactly 40 lower-case hex characters;
4. parses `job_workflow_ref` as `<owner>/<repo>/<path>@<ref>` and requires:
   - the repository to be `IamRitz/ssd-security-framework`, compared
     case-insensitively, as GitHub owner and repository names are.
     Capitalization is never part of the security boundary;
   - the path to be exactly `.github/workflows/_break-glass-lambda.yml`;
   - a non-empty ref. The ref may be a commit SHA, a tag or a branch: it is
     **not** what is authorized;
5. outputs `job_workflow_sha`.

Then:

6. the framework is checked out **only** at that output;
7. the checkout's `HEAD` must equal it, or the job fails;
8. `inputs.toolkit_ref` selects nothing. It stays an input for v1
   compatibility; when it differs from `job_workflow_sha`, the job emits a
   notice and carries on;
9. no later step uses `toolkit_ref` for anything security-relevant.

The step order is the control, and `test/break-glass-oidc-boundary.test.js`
asserts it.

### 2. Only `_break-glass-lambda.yml` may ask

The legacy `_source-security.yml` `source-gate` job also holds
`id-token: write`, but it checks out the consumer repository and accepts a
caller-chosen `toolkit_repository` and `toolkit_path`. Code its caller controls
can run there, so no commit of it can vouch for a request. The broker refuses
it (`job_workflow_path_not_allowed`). Its `http` transport never reached the
Lambda broker, and hardened production supports the **Lambda transport only**
([break-glass-setup.md § Transports](break-glass-setup.md#transports)).

### 3. The broker admits commits per environment

After the token's signature and claims are verified
([break-glass-setup.md § Who is asking](break-glass-setup.md#who-is-asking-verified-github-identity)),
the broker requires:

- `job_workflow_ref` to name the framework repository (case-insensitively)
  and exactly the path `.github/workflows/_break-glass-lambda.yml`, as in
  step 4 above;
- the verified `job_workflow_sha` to be in **this environment's** allowed set.

A tag or branch spelling is not refused for being a tag or a branch. It is
decided by the commit it resolved to: when `@v1` moves to a commit that is not
admitted, `job_workflow_sha` changes and the request is refused; an admitted
commit stays admitted however the caller spelled the ref. Pinning callers to an
exact SHA is still recommended, as supply-chain hardening
([versioning.md](versioning.md#the-toolkit_ref-duplication-and-why-it-exists)),
but it is not the authorization mechanism.

The check runs at three points:

| When | Order | Not admitted |
| --- | --- | --- |
| `notify` | token verified → **commit checked** → token's `jti` claimed (the first write) | `403 framework_rejected: framework_sha_not_allowed`; nothing is written |
| every `status` | the same | the same; the CI poll fails and the BLOCK stands |
| an approver's click | the approver list and the commit of the **stored** request are read in parallel; approver authorization is decided first | outcome `revoked`: the request is not claimed and simply expires |

The click-time check means removing a commit also revokes its pending
requests. A policy that cannot be read (SSM refused, failed or slower than
2 s), is absent, or is malformed admits nothing:
`503 framework_policy_unavailable: <state>`. Each refusal is logged with the
commit, `repository_id` and run, never the token.

The CI broker reads its Slack credential only when it posts. Identity and
commit checks therefore never read a secret, and a refused request touches
none. A successful secret read is cached for the warm container; a failed one
is not.

## The allowed-commit parameter

| | |
| --- | --- |
| Stack | `ssd-break-glass-<env>-governance`, one per environment |
| Resource | `AWS::SSM::Parameter`, logical id `AllowedFrameworkShas` |
| Name | `/ssd/break-glass/<env>/governance/allowed-framework-shas` |
| Type | `String`, tier `Standard`, data type `text` |
| Value | `{"schemaVersion":1,"environment":"<env>","shas":["<sha>",…]}` |

The value is canonical and byte-exact: those three keys in that order, the
SHAs as 40 lower-case hex characters in strictly ascending order (no
duplicates), at most 64 of them, at most 4096 bytes. `"shas": []` is valid and
admits nothing. The broker refuses a value whose `environment` is not its own,
so a production value copied into the synthetic parameter (or the reverse)
admits nothing.

**Admission.** `aws plan` refuses, and `aws verify` reports as FAIL, any
listed commit that:

- does not exist in the framework checkout plan runs from;
- has a `.github/workflows/_break-glass-lambda.yml` without the binding above
  (the step `id: bind-framework-commit` and a checkout of
  `ref: ${{ steps.bind-framework-commit.outputs.sha }}`), or that still checks
  out `inputs.toolkit_ref`;
- for **production only**, is not an ancestor of `refs/remotes/origin/main`.
  The plan records the `origin/main` commit it checked against.

**Synthetic is deliberately broader:** a candidate commit that is not yet
merged may be admitted to synthetic, explicitly, to test it live. It is never
thereby admitted to production: the two environments have separate
parameters, separate configuration files and separate readers.

**Who may change it.**

| Principal | Access |
| --- | --- |
| CloudFormation, run by the scoped deployer through `aws plan` / `aws apply` | writes |
| the bootstrap admin | only a reviewed emergency revoke (`"shas": []`), which `aws verify` then reports as drift |
| this environment's CI and interaction execution roles | `ssm:GetParameter` on this exact ARN, nothing else |
| invoker roles, consumer repositories, the other environment's roles | nothing |

To revoke a commit, remove it from the configuration and apply. Deleting the
stack does not revoke anything (Retain): empty the list first.

## The per-repository stack

### Invoker role: `ssd-break-glass-<env>-invoker-<repository_id>`

Trust, identical for production and synthetic in 3D:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PullRequestRunsOfOneRepository",
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "<subject>"
      }
    }
  }]
}
```

- `<subject>` is GitHub's default `repo:<owner>/<repo>:pull_request`, with
  `<owner>/<repo>` exactly as the GitHub API's `full_name` spells it.
- A **customized** subject (for example the immutable
  `repo:<owner>@<owner_id>/<repo>@<repo_id>:…` form) is used only when the
  repository's OIDC customization is confirmed live **and** the subject GitHub
  actually emits is proven from a recorded run ([below](#repository-configuration)).
  A subject is never inferred or constructed from owner and repository ids.
- There is no `ref:refs/heads/*` subject (the broker refuses every non-PR
  event), no `job_workflow_ref` condition, and no `StringLike`.
- `MaxSessionDuration` is 3600.

Any job of the repository's `pull_request` runs can assume the role. That is
deliberate and sufficient: its one permission is to invoke the CI broker, and
the broker refuses every token that does not come from
`_break-glass-lambda.yml` at an admitted commit. Fork pull requests receive no
OIDC token at all.

Permissions, one inline policy `ssd-break-glass-invoke-ci`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "InvokeCiBrokerOnly",
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:<region>:<account>:function:ssd-break-glass-<env>-ci"
  }]
}
```

The ARN is unqualified: no `:*`, version or alias. The CI broker has no
resource policy, so this is its only grant. **IAM does not separate one
repository from another here**: every repository's role in an environment
invokes the same function. Repositories are separated by the verified token
identity and by approvers keyed on `repository_id`.

### Approver parameter: `/ssd/break-glass/<env>/approvers/<repository_id>`

`AWS::SSM::Parameter`, `String`, `Standard`, `text`, value
`JSON.stringify(<approvers>)` from the configuration. It is validated with the
broker's own parser (`broker/authorize/approvers.mjs`): at most 50 Slack user
ids (`U…`/`W…`), no duplicates.

**`[]` is valid** and authorizes nobody. It is how a repository is offboarded:
set `[]`, apply, and only then remove anything (Retain keeps the parameter).
Missing, `[]`, malformed and unreadable all authorize nobody, at click time
([break-glass-setup.md § Authorization](break-glass-setup.md#authorization-is-per-repository-and-fail-closed)).
`aws verify` reports `[]` as a WARN, "enabled but not operationally ready",
and never as a reason to authorize. An urgent revoke is
`put-parameter --overwrite` with `[]`: it fails closed, and verify reports it
as drift until the configuration matches.

## Configuration

Phase 3D configuration is operator-owned and always named explicitly.
`.ssd/onboarding.yml` is never read, so a consumer repository cannot choose its
approvers or its AWS authority. `break-glass.yml` (`--operator-config`) is
unchanged; it supplies the framework commit, account and region.

### Framework policy (one file per environment)

```yaml
schemaVersion: "1"
kind: break-glass-framework-policy
environment: synthetic            # must equal --environment
allowedFrameworkShas:             # 0..64, 40 lower-case hex, no duplicates
  - <sha>
```

### Repository configuration

```yaml
schemaVersion: "1"
kind: break-glass-repository
repository:
  slug: owner/repo                # must equal GitHub's full_name, ignoring case
  id: "123456789"                 # the immutable repository_id
environments:                     # at least one; an absent environment is not onboarded there
  synthetic:
    approvers: ["U0123456789"]
  production:
    approvers: []                 # valid: nobody
# Only for a repository whose OIDC subject is customized:
# oidc:
#   subject: <the exact subject GitHub emits for pull_request runs>
#   observedRunId: "<id of the run that recorded it>"
```

Everything else is derived: stack, role, policy and parameter names, the CI
function ARN and the OIDC provider ARN. Unknown keys and credential-shaped
values refuse the file.

`aws plan --scope break-glass-repo` blocks unless:

- the framework checkout is bound to `framework.ref`, and the caller is the
  configured account;
- the environment's shared stack is settled and owned;
- the account's GitHub OIDC provider exists with client id `sts.amazonaws.com`
  (read-only; this plan never creates it);
- `gh api repos/<slug>` returns this `id` and a matching `full_name`;
- `gh api repos/<slug>/actions/oidc/customization/sub` reports the default
  subject, **or** it reports a customization and `oidc.subject` equals the
  subject printed by the recorded run `oidc.observedRunId` of that repository;
- the role and the parameter are absent or already this stack's own resources.
  A resource that merely has the name is never adopted.

If `gh` is unavailable, the plan blocks: the `repository_id` is what approvers
are keyed on, so it is never taken on trust.

## Changes to the shared stacks

| Role or function | Change |
| --- | --- |
| CI execution role | add `ssm:GetParameter` on exactly this environment's `governance/allowed-framework-shas` |
| interaction execution role | add the same grant (the click-time check) |
| CI function | add `BREAK_GLASS_ENVIRONMENT=<env>` |

No wildcard is added. The interaction role's `approvers/*` grant does not
match `governance/…`. The broker code changes, so the shared stacks are
updated with a new published artifact; for synthetic that is an in-place
modification of both functions and both role policies, never a replacement.

## Commands

```
ssd-onboard aws plan   --scope break-glass-governance --environment <env> --operator-config break-glass.yml --policy-config <file>
ssd-onboard aws plan   --scope break-glass-repo       --environment <env> --operator-config break-glass.yml --repository-config <file>
ssd-onboard aws apply  --plan-id <id> --account <id> --region <r> --operator-config break-glass.yml (--policy-config | --repository-config) <file>
ssd-onboard aws verify --scope break-glass-governance|break-glass-repo --environment <env> --operator-config break-glass.yml (--policy-config | --repository-config) <file>
```

A plan is applied only with the files it was made from, unchanged.

## Verification

Effective access comes from `iam simulate-principal-policy`, as in 3C.

**Invoker role.** Required: `lambda:InvokeFunction` on this environment's CI
broker. Each of these must be denied:

| Action | Resource |
| --- | --- |
| `lambda:InvokeFunction` | the CI broker qualified (`:$LATEST`); this environment's interaction function; the other environment's two functions; an unrelated function |
| `lambda:InvokeFunctionUrl`, `lambda:InvokeAsync` | the interaction function; the CI broker |
| `lambda:GetFunction`, `GetFunctionConfiguration`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `AddPermission`, `CreateFunctionUrlConfig`, `PutFunctionConcurrency` | the CI broker |
| `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Query`, `Scan` | both environments' tables |
| `secretsmanager:GetSecretValue`, `DescribeSecret`, `PutSecretValue` | all six broker secrets |
| `ssm:GetParameter`, `PutParameter`, `DeleteParameter` | its own approver parameter, another repository's, both allowed-commit parameters |
| `iam:PassRole`, `sts:AssumeRole` | the execution roles; another invoker role |
| `logs:CreateLogStream`, `logs:PutLogEvents` | both functions' log groups |

Its trust is also evaluated offline: the configured subject assumes; another
repository (either subject form), the same repository's `ref:refs/heads/main`
or `environment:` subject, another audience and any wildcard do not.

**Approver parameter.** Owned by the stack; `String`/`Standard`; value
byte-equal to the configuration and accepted by the broker's parser; `[]` is a
WARN. This environment's interaction role may read it; the other
environment's may not; the CI role may not.

**Allowed-commit parameter.** Owned; `String`/`Standard`; byte-equal to the
configuration and accepted by the broker's parser; every commit meets the
admission rules. This environment's CI and interaction roles may read it; the
other environment's roles, the invoker roles and the execution roles may not
write it. Which other principals could write it cannot be enumerated from IAM,
and is reported as NOT VERIFIED.

**Shared stacks.** The 3C checks, plus: both execution roles read their own
allowed-commit parameter and not the other environment's, and the CI function
carries `BREAK_GLASS_ENVIRONMENT`.

## Live validation (synthetic only)

The 3D merge gate runs against the synthetic stacks. Slack secrets stay empty,
so no probe needs Slack:

1. the synthetic governance stack, shared-stack update and one scratch
   repository's stack are planned, applied and verified;
2. from a `pull_request` run of that repository, a job that assumed the
   invoker role can invoke the CI broker (a status call without a token is
   refused `token_missing`, which proves the broker started with empty
   secrets), its own token is refused (`job_workflow_path_not_allowed` or
   `job_workflow_repository_not_allowed`), and every negative action above is
   AccessDenied;
3. `push` and `workflow_dispatch` runs of that repository, and any run of a
   second repository, cannot assume the role;
4. `_break-glass-lambda.yml` at an admitted commit with a synthetic fixture is
   accepted up to the Slack post, which fails (`502 slack_post_failed`, the
   request rolled back). A different `toolkit_ref` changes nothing but a notice;
5. the same at a commit that is **not** admitted is refused
   `framework_sha_not_allowed`, and nothing is written.

Approver clicks, the click-time revoke, and the race and timeout suite need
Slack and move to Phase 3E.

## Not in Phase 3D

- Production stacks of any kind (pre-production gate,
  [break-glass-provisioning.md](break-glass-provisioning.md#pre-production-gate-after-3d-and-3e)).
- Secret values and Slack configuration.
- The synthetic workflow contract and the `verify-live` suite (3E).
- Generated break-glass callers: Phase 1 still generates none
  ([architecture B.8](onboarding-architecture.md#b8-break-glass-is-not-generated-choice-b)).
