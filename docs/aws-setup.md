# AWS reference

[`onboarding.md`](onboarding.md) is the checklist. This is the reference behind
it: why the roles are split the way they are, how the digest chain holds
together, and the details that cost real debugging time.

Applies only to repos declaring `registry: ecr` or
`deploy_target: framework-gated`.

## The digest chain (scanned == deployed)

The thing Trivy scanned, the thing the registry scanned, and the thing that runs
are bound to a single immutable digest, so a mutable tag can never be swapped in
between:

1. **build → scan** — `_image-scan-prepush.yml` records Trivy's
   `Metadata.ImageID` (the image *config* digest) as a workflow output.
2. **scan → push** — `_ecr-collect.yml` asserts the loaded artifact's
   `docker inspect .Id` equals that ImageID before pushing, then records the
   pushed **manifest** digest.
3. **push → registry scan** — the same collector polls
   `--image-digest <that manifest digest>`, and the poller asserts the registry
   scanned exactly that digest.
4. **scan → gate** — `_artifact-gate.yml` re-asserts the report's digest equals
   the `expected_digest` the collector pushed, before evaluating policy.
5. **gate → deploy** — the deploy pulls `registry/repo@sha256:…`, never a tag.

Each link is an assertion that fails closed, not a convention. Remove any one of
them and "we scanned it" stops implying "we shipped it".

**The canonical caller that wires this up is
[`examples/container-ecr/deploy.yml`](../examples/container-ecr/deploy.yml).**
It is the `delivery` phase: the PR caller (`security.yml`) proves the source and
pre-push image controls, and this one proves registry collection, the artifact
gate, and the deploy. Copy it rather than assembling the chain by hand — every
link above is one `with:` line in that file, and a missing one is a silent
weakening rather than an error.

Note how the credentials are split across jobs there: the build holds none, the
collector holds only the push+scan role, the artifact gate holds none, and the
deploy holds only SSM. Collapsing those into one privileged job would put
untrusted build code in the same process as deploy credentials.

## Why two roles, not one

| Role | Assumed by | Holds |
| --- | --- | --- |
| push+scan | `_ecr-collect.yml` | ECR write + `DescribeImageScanFindings` on one repository |
| deploy | the caller's own deploy job | `ssm:SendCommand` + `ssm:GetCommandInvocation` only |

ECR push and scan-findings read are both registry operations on the same
repository, so they share a role. The **deploy** role — the credentials that can
reach the instance — stays separate. The boundary that matters is that **no
single role can both push an image and deploy it**.

`_image-scan-prepush.yml` and `_artifact-gate.yml` assume no role at all: they
only scan a tarball and evaluate a report. Neither declares `id-token`, which is
what makes OIDC role assumption possible in the first place — asserted in the
framework's tests.

The instance pulls the image with its **own** read-only ECR role
(`AmazonSSMManagedInstanceCore` plus ECR pull). No runner credential ever
reaches the box.

## Details that cost time

**`ssm:GetCommandInvocation` cannot be scoped to the instance.** It must be
granted on `*`. Scoping it to the instance ARN silently denies the read-back:
the command runs, the deploy job waits for a result it can never read, hangs,
and then fails.

**`ssm:SendCommand` needs both ARNs** — the instance *and* the
`AWS-RunShellScript` document. Granting only the instance denies the call.

**`ssm:SendCommand` is not read-only.** `AWS-RunShellScript` runs arbitrary
shell as root on the target. Any identity holding it can change that instance.
Scope it to one instance and one document, and treat it accordingly.

**Enhanced scanning needs the Inspector statement.** With enhanced scanning,
`ecr:DescribeImageScanFindings` reads coverage and findings from Inspector on
the caller's behalf, so the ECR permission alone is not enough. A role with only
the ECR statement fails with `AccessDeniedException … not authorized to perform:
inspector2:ListCoverage`, on every attempt, and the gate correctly fails closed
with no deploy. The collector also calls both APIs directly, because a clean
enhanced scan returns `COMPLETE` with no severity counts — the same body as a
scan whose findings have not attached yet. Before reporting an image clean, the
poller requires Inspector coverage showing that digest scanned plus zero
findings for it; anything else waits, then fails closed.

**Both list APIs are account-level** with no per-repository ARN, hence
`Resource: "*"`. Both are read-only. Basic scanning needs neither.

## Basic vs enhanced scanning

| | Basic | Enhanced (Inspector) |
| --- | --- | --- |
| Scope | per repository | **registry-wide, per region** — scope with inclusion filters |
| Cost | free | per image scanned, plus continuous rescanning |
| Fix availability | **not reported** | reported |
| Gate behaviour | severity-only: all Critical/High block | with-fix blocks, no-fix is a tracked EXCEPTION |

The asymmetry is a scanner limitation, not a policy choice. Basic cannot tell
you whether a fix exists, so the gate conservatively blocks rather than guessing
"no fix" and letting it through.

The enhanced response shape is the source of a real incident class: an enhanced
body carries findings in `enhancedFindings[]` **and an empty `findings: []`
alongside it**, so a basic-only parser reads it as a clean scan. Two guards
prevent that — the mode is derived from which arrays are populated (both
populated is ambiguous and fails closed), and parsed findings must reproduce the
registry's own `findingSeverityCounts` exactly, per severity.

## Local operator identity: never the root user

Use the account root user only for operations that genuinely require it —
account settings, root credentials, restoring IAM access after a lockout,
closing the account. Root cannot be scoped, cannot carry a permission boundary,
and cannot be safely revoked if leaked.

For manual work against the environment, use a dedicated IAM user with an inline
least-privilege policy: Inspector read, ECR read on the one repository, and
`ssm:SendCommand` confined to the one instance and the one document. Verify it
by confirming the **negative** cases — that `iam list-users`, an unscoped
`ecr describe-repositories`, and `send-command` with a different document are
all denied. A policy you have only tested positively is a policy you have not
tested.

If that identity uses a long-lived access key, rotate it after use and delete it
with the environment.

## Provisioning that the operator identity cannot do

A correctly scoped operator identity deliberately **cannot** create Lambda
functions, IAM roles, or DynamoDB tables. That is the policy working, not a
problem to route around.

Provision those through a session with the appropriate console identity (AWS
CloudShell is convenient for this). **Do not widen the operator identity to make
a provisioning step succeed**, and do not fall back to root: a temporary
widening to unblock one task is how least privilege quietly stops being true.

## Verification

```sh
# Who am I really? Must not be :root.
aws sts get-caller-identity

# The scan the gate will read, for the exact digest that was pushed.
aws ecr describe-image-scan-findings \
  --repository-name <REPO> --image-id imageDigest=<sha256:...> --region <REGION>

# The required checks branch protection actually has.
gh api repos/<org>/<repo>/branches/main/protection/required_status_checks
```

Confirm a saved branch-protection rule by reopening it in the UI as well. A rule
that exists but is not enforced by the plan is not a control.
