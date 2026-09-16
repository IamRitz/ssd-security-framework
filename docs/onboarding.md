# Onboarding a repository

This is the complete setup: the repo side, the AWS side, the break-glass side,
and the order to switch things on in.

**Read the scope markers.** Most onboarding friction comes from conflating three
different kinds of step:

| Marker | Meaning |
| --- | --- |
| **[ORG]** | Once per organization. Doing it again is a no-op or a mistake. |
| **[ACCOUNT]** | Once per AWS account *(and sometimes per region — noted where it matters)*. |
| **[REPO]** | Every repository. This is the actual onboarding checklist. |

If you are onboarding the second repo into an account that already runs this
framework, you can skip every **[ORG]** and **[ACCOUNT]** step and go straight to
[Part 1](#part-1-the-repository-repo).

---

## Before you start: what does this repo actually need?

Not every repo needs the AWS parts. Decide this first, because it determines
which half of this document applies.

| If the repo… | You need | Declare |
| --- | --- | --- |
| ships a library, a static site, or nothing deployable | Part 1 only. No AWS at all. | `artifact_type: library` (or `none`), `registry: none`, `deploy_target: none` |
| builds a container but pushes and deploys it through an existing pipeline | Part 1 only. The image is still scanned before it leaves CI. | `artifact_type: container`, `registry: none`, `deploy_target: self-managed` |
| builds a container and you want the framework to push, scan, and gate the deploy | Parts 1 and 2 | `artifact_type: container`, `registry: ecr`, `deploy_target: framework-gated` |
| wants a human override for an eligible BLOCK | Part 3 as well | `break_glass_enabled: true` |

A repo that already has a delivery pipeline **does not have to give it up**. The
framework's source and pre-push image controls work with no registry and no
deploy at all. `deploy_target: self-managed` is a first-class answer, and the
conformance report says so in words rather than leaving a hole.

---

## Part 1 — The repository **[REPO]**

### 1.1 Generate the Semgrep baseline FIRST

Do this before you enable anything. A repo that has never had SAST has a
backlog. If you turn on a blocking gate cold, the first PR fails on hundreds of
pre-existing findings its author did not write, and the team's correct
conclusion is that the tool is broken.

The baseline records the current state as *known*, so the gate blocks only what
a change **introduces**.

```sh
semgrep scan \
  --config p/owasp-top-ten \
  --config p/javascript \
  --json-output=semgrep.json \
  src
```

Then generate the baseline through the framework's own generator, not by hand:

```sh
node <toolkit>/security/scripts/generate-semgrep-baseline.mjs \
  --report semgrep.json \
  --gate reports/security-gate.json \
  --rulesets "p/owasp-top-ten p/javascript" \
  --output security/baseline/semgrep-baseline.json
```

Commit `security/baseline/semgrep-baseline.json`.

> **The generator refuses to run from an untrusted scan.** It hard-fails unless
> every supplied gate result reports `integrity.trusted: true`. A scan whose
> input could not be interpreted reports zero findings, and baselining that
> writes "no findings" into permanently accepted state. This is why you generate
> the baseline from a real `log-only` CI run rather than from a partial local
> scan — and why a run that produced `reports/DO-NOT-BASELINE.txt` must not be
> used.

The easier route is to run the pipeline in `log-only` first (§1.5), download the
`security-gate-results` artifact, and generate from that.

`--baseline-commit` (which controls what Semgrep *scans*) is a different thing
from this baseline file (which controls what the gate *blocks*). Keep both.

### 1.2 Add the caller workflow

Copy the closest example:

| Example | For |
| --- | --- |
| [`examples/source-only/security.yml`](../examples/source-only/security.yml) | libraries, static sites, anything with no container |
| [`examples/python-self-managed/security.yml`](../examples/python-self-managed/security.yml) | a Python service with its own deploy pipeline |
| [`examples/container-ecr/security.yml`](../examples/container-ecr/security.yml) | the full path: container → ECR → gated deploy |

Two things to get right:

- **`semgrep_configs` must match the repo's language.** `p/javascript` on a
  Python repo reports near-zero findings, which looks like a clean pass rather
  than a misconfiguration. This is the same false-clean failure mode as a
  scanner failing to identify a base image. The workflow refuses to run with an
  empty ruleset, but it cannot tell that your rules are for the wrong language.
- **`toolkit_ref` must match the `@ref` in the `uses:` line.** See
  [versioning.md](versioning.md#the-toolkit_ref-duplication-and-why-it-exists)
  for why this duplication exists.

Nothing else is copied. No scripts, no policy — see
[toolkit-resolution.md](toolkit-resolution.md).

### 1.3 Declare capabilities

Add the `conformance` job from your example and set the three values from the
table at the top of this document.

Controls that do not apply are reported **N/A with a reason**. This is not the
same as skipping them, and deliberately not the same as exempting them:

- **N/A** — a stable fact about what this repo is. A library has no image.
- **Exempt** — a control that *applies*, deliberately not enforced. It is debt:
  it needs an owner and an expiry, and it expires closed.

To exempt something, add `security/exemptions.json`:

```json
[
  {
    "control": "image-scan-prepush",
    "reason": "base image upgrade blocked on the platform team's Q3 rollout",
    "owner": "platform-security",
    "expires": "2026-12-31"
  }
]
```

All four fields are required. An exemption nobody owns, or one that never
expires, is how a temporary decision becomes permanent silently. After the
expiry date it grants nothing and the control fails again.

### 1.4 CODEOWNERS on the security paths

`gate_mode: log-only` makes the gate genuinely non-blocking — that is the point
of the rollout, but it also means **one line in an app-team-owned workflow turns
a red required check green**, reviewed by whoever normally reviews that repo's
code. Without CODEOWNERS, a repo has an unreviewed path to bypassing its own
security gate.

```
# .github/CODEOWNERS
/.github/workflows/          @your-org/security-engineering
/.github/CODEOWNERS          @your-org/security-engineering
/security/baseline/          @your-org/security-engineering
/security/exemptions.json    @your-org/security-engineering
/security/policy.yaml        @your-org/security-engineering
```

**This file alone enforces nothing.** It is advisory until branch protection
enables *Require review from Code Owners* with at least one required approval
(§1.6). Own it with a team, not an individual, so review does not depend on one
person's availability.

### 1.5 Start in log-only

Set the repo variable `GATE_MODE=log-only`, or use the `log-only` default in the
source-only example. Everything runs and reports; nothing fails; no Slack.

Expect a `gate-mode: LOG-ONLY (gate NOT enforcing)` check on every PR. That
check going away is how you know the repo reached enforcement; it reappearing is
how you notice a regression.

### 1.6 Branch protection **[REPO]**

Once the pipeline has produced the `security-gate` check at least once:

1. **Settings → Branches**, add or edit the rule for `main`.
2. Enable **Require status checks to pass before merging**.
3. Require `security-gate` — and your own test check.
4. Enable **Require review from Code Owners** and set at least 1 approval,
   or §1.4 is decorative.
5. Disable administrator bypass; disable force pushes and branch deletion.

Verify:

```sh
gh api repos/<org>/<repo>/branches/main/protection/required_status_checks
```

Two caveats worth knowing:

- **The required check name is a constant.** `security-gate` is republished by a
  thin job in the caller because a reusable workflow reports its inner jobs as
  `caller-job / inner-job`. If you rename that job, the rule matches nothing and
  merges silently stop being gated, with nothing visibly failing.
- **Required-check enforcement depends on the plan.** GitHub Free does not
  enforce branch protection on *private* repositories. A visible but unenforced
  rule is not a control. Confirm enforcement, or treat the job DAG as your only
  real gate.

Even where branch protection cannot be relied on, the delivery jobs carry
`needs:` plus an explicit `if: github.ref == 'refs/heads/main' && …success()`
chain, so a failing gate still prevents push and deploy. Branch protection is
the front door; the job DAG is the deadbolt behind it.

---

## Part 2 — AWS **[ACCOUNT]** unless marked otherwise

Skip this entire part if `registry: none` and `deploy_target` is not
`framework-gated`.

### 2.1 The OIDC identity provider — **one per account** **[ACCOUNT]**

```sh
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

**One per AWS account, not per repository.** Creating a second one for the
second repo fails, and hunting that error is a classic waste of an afternoon. If
your account already federates GitHub Actions, it already exists — reuse it.

### 2.2 IAM roles and the trust policy **[REPO]**

Roles are per repository, because the trust policy names the repository.

Create **two** roles per repo. ECR push and scan-findings read are both registry
operations and share one role; the SSM deploy role — the credentials that can
reach the instance — stays separate. No single role can both push an image and
deploy it.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:ref:refs/heads/main"
      }
    }
  }]
}
```

#### The `StringEquals` + wildcard trap

This is the single most common way to lose a day here:

```jsonc
// BROKEN — matches nothing, ever.
"StringEquals": {
  "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
}
```

`StringEquals` does **exact string comparison**. It does not expand `*`. A
wildcard under `StringEquals` matches no real subject, so every `AssumeRole`
fails — and it fails with a generic "not authorized to perform
sts:AssumeRoleWithWebIdentity", which does not mention the wildcard. The policy
*looks* more permissive than an exact match while actually being more
restrictive than any.

Use the right operator for what you mean:

| Intent | Operator | Value |
| --- | --- | --- |
| Only `main` (recommended) | `StringEquals` | `repo:org/repo:ref:refs/heads/main` |
| Any branch or tag in one repo | `StringLike` | `repo:org/repo:*` |
| A GitHub Environment | `StringEquals` | `repo:org/repo:environment:production` |

Never broaden `sub` to all repositories, and never include pull-request
subjects for a role that can push or deploy — a PR from a fork must not be able
to assume it.

> **Check the real claim before trusting any example.** Repositories created
> after GitHub introduced immutable OIDC subjects use permanent numeric owner and
> repository IDs in `sub`
> (`repo:org@<owner-id>/<repo>@<repo-id>:ref:refs/heads/main`). Print the actual
> claims from a job and copy from that, rather than assuming the format.

#### Permission policies

**Push+scan role** — ECR write plus scan-findings read on this repo, no SSM:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*" },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart",
        "ecr:DescribeImageScanFindings"
      ],
      "Resource": "arn:aws:ecr:<REGION>:<ACCOUNT_ID>:repository/<REPO_NAME>"
    },
    {
      "Sid": "OnlyNeededForEnhancedScanning",
      "Effect": "Allow",
      "Action": ["inspector2:ListCoverage", "inspector2:ListFindings"],
      "Resource": "*"
    }
  ]
}
```

**The Inspector statement is required for enhanced scanning and only then.**
With enhanced scanning, `ecr:DescribeImageScanFindings` reads from Inspector on
your behalf, so the ECR permission alone is not enough — a role with only the ECR
statement fails with `AccessDeniedException … inspector2:ListCoverage`. These are
account-level list APIs with no per-repository ARN, hence `Resource: "*"`; both
are read-only. Basic scanning does not need them.

**Deploy role** — SSM only, and **no ECR access at all**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ec2:<REGION>:<ACCOUNT_ID>:instance/<INSTANCE_ID>",
        "arn:aws:ssm:<REGION>::document/AWS-RunShellScript"
      ]
    },
    { "Effect": "Allow", "Action": "ssm:GetCommandInvocation", "Resource": "*" }
  ]
}
```

`ssm:SendCommand` needs **both** the instance ARN and the document ARN.
`ssm:GetCommandInvocation` **cannot be scoped to the instance** — scoping it
silently denies the read-back and the deploy hangs, then fails. The instance
pulls the image with its *own* read-only ECR role, so the runner's push
credentials never reach the box.

### 2.3 ECR repository and scanning **[REPO]** + **[ACCOUNT/REGION]**

Create the repository **[REPO]**:

```sh
aws ecr create-repository \
  --repository-name <REPO_NAME> \
  --image-scanning-configuration scanOnPush=true \
  --region <REGION>
```

#### Enhanced scanning is registry-level, per region — **[ACCOUNT/REGION]**

This surprises people. Enhanced scanning (Amazon Inspector) is **not** a
per-repository setting. Enabling it applies to the **whole registry in that
region**, so turning it on for one repo turns it on for every repo in that
account and region.

Scope it with **inclusion filters** rather than enabling it registry-wide:

```sh
aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{
    "scanFrequency": "SCAN_ON_PUSH",
    "repositoryFilters": [{"filter": "my-team-*", "filterType": "WILDCARD"}]
  }]' \
  --region <REGION>
```

Without a filter you have just enrolled every image in the region, including
other teams', and you will see it on the bill before you see it in a review.

**The cost model, in shape rather than numbers** (check current Inspector
pricing — it changes):

- You are billed **per image scanned**, and again for **continuous rescanning**
  as new CVEs are published, for a retention window after push.
- The driver is therefore **how many distinct images you keep**, not how many
  times you deploy. A pipeline that pushes a commit-SHA tag on every merge
  accumulates images that keep being rescanned.

So pair it with a **lifecycle policy** **[REPO]**, which is a cost control as
much as a hygiene one:

```json
{
  "rules": [{
    "rulePriority": 1,
    "description": "Expire untagged and old commit-tagged images",
    "selection": {
      "tagStatus": "any",
      "countType": "imageCountMoreThan",
      "countNumber": 30
    },
    "action": { "type": "expire" }
  }]
}
```

Keep enough images to roll back to; expiring them stops the rescan meter.

Basic scanning is free, per-repository, and reports **no fix availability** — so
the gate falls back to severity-only and conservatively blocks all Critical/High.
Enhanced reports fix availability and uses the same with-fix/no-fix model as
dependencies. That asymmetry is a scanner limitation, not a policy choice.

### 2.4 Repository variables **[REPO]**

Variables, not static AWS secrets:

| Variable | Example |
| --- | --- |
| `AWS_PUSH_SCAN_ROLE_ARN` | `arn:aws:iam::123456789012:role/<repo>-ecr-push-scan` |
| `AWS_DEPLOY_ROLE_ARN` | `arn:aws:iam::123456789012:role/<repo>-deploy` |
| `AWS_REGION` | `us-east-1` |
| `ECR_REPOSITORY` | `<repo-name>` |
| `EC2_INSTANCE_ID` | `i-0123456789abcdef0` |
| `GATE_MODE` | `log-only` during rollout, then unset or `enforce` |

If any are missing, the AWS stages detect that and **visibly skip** rather than
failing — so a repo can adopt Part 1 today and Part 2 later.

### 2.5 If the repo already pushes to a registry

You have three honest options:

1. **Keep your pipeline, add the pre-push gate.** Declare `registry: none`,
   `deploy_target: self-managed`, and call `_image-scan-prepush.yml` on the
   tarball you already build. The image is scanned before it leaves CI. The
   registry-side controls report N/A with that reason.
2. **Move the push into the framework.** Use `_ecr-collect.yml`, get the digest
   chain and the artifact gate. Most work, strongest guarantee.
3. **Write a collector for your registry.** `_artifact-gate.yml` names no
   registry: it consumes a normalized report. A sibling `_gar-collect.yml` or
   `_acr-collect.yml` that emits the same schema plugs straight in. The gate and
   the policy do not change.

What you should **not** do is declare `registry: ecr` because it sounds more
complete. A capability declaration that does not match reality produces a
conformance report that disagrees with the pipeline, and the report will say so.

---

## Part 3 — Break-glass **[ACCOUNT]** + **[REPO]**

Break-glass lets a human approve an **eligible** BLOCK. Eligibility is narrow
and decided by policy, not by the approver:

| Eligible | Never eligible |
| --- | --- |
| a new high/critical SAST finding | a verified secret |
| a fixable high/critical dependency finding | a known-malicious (`MAL-`) package |
| | a report-integrity failure |

Dependency findings with **no fix available** are not eligible either — the gate
already treats them as EXCEPTION, so there is nothing to override.

The CI side checks eligibility **before** any approval credential is loaded, so a
hard block never reaches the approval channel at all.

### 3.1 Broker infrastructure **[ACCOUNT]**

Once per account, shared by every repo:

- **Lambda** — the request/decision broker, plus the Slack interaction handler.
- **DynamoDB** — the pending-request table. The `pending → processing →
  approved|denied` transition is a conditional write, which is what makes a
  double-click race impossible rather than unlikely.
- **Secrets Manager** — the Slack bot token and the Slack signing secret.

### 3.2 The invoker role **[REPO]**

A dedicated OIDC role that can invoke **only** the break-glass function — not
the interaction handler, not the DynamoDB table, not the secrets. Scope its
trust policy the same way as §2.2, and confirm the negative case: assuming it
and calling anything else must return AccessDenied.

Pass it as `break_glass_lambda_role_arn` with `break_glass_transport: lambda`.
This path needs **no repository secret at all**.

### 3.3 The Slack app **[ORG]**

Once per Slack workspace:

1. Create the app; add the **`chat:write`** bot scope. That is the only scope
   needed.
2. Install it and **invite the bot to the approval channel** — otherwise
   `chat.postMessage` returns `not_in_channel`.
3. Store the **bot token** and the **signing secret** in Secrets Manager. The
   signing secret is an HMAC key: it verifies that a button click really came
   from Slack.
4. Turn **Socket Mode off**. The design needs a signed HTTP POST to a Request
   URL; Socket Mode bypasses exactly that.
5. Set the **Interactivity Request URL** to the live interaction endpoint.

> **The URL must already be live and responding when you save it.** Slack sends
> a verification request at save time and rejects the URL if it does not get a
> valid signed response. Deploy the handler *first*, then paste the URL. Doing it
> in the other order fails confusingly.

### 3.4 Per-repo approvers **[REPO]**

Authorization is per repository and fail-closed:

```
SLACK_APPROVER_IDS_BY_REPO={"org/repo-a":["U123"],"org/repo-b":["U456","U789"]}
```

- A repository **not present as a key authorizes nobody.** There is no fallback
  to a shared default list. A repo is not onboarded to break-glass until it has
  an explicit entry.
- **Malformed JSON is treated as an empty map** — nobody authorized for
  anything — logged, never thrown. One bad edit cannot crash approvals for every
  repo at once.
- The repository identity comes from the **stored pending request**, looked up by
  request ID when the click arrives — never from the Slack payload, which has no
  notion of a GitHub repo and so offers nothing to forge.

Changing this is an environment-variable change, which needs a restart of the
handler to take effect.

### 3.5 A repo with no Slack

**Break-glass is simply unavailable, and that is a supported configuration.**

Set `break_glass_enabled: false` (the default). An eligible BLOCK then behaves
exactly like any other BLOCK: it fails, and the fix is to fix the finding. The
conformance report records the break-glass control as **N/A**, with the reason
`break_glass_enabled=false`, rather than as a gap.

This is worth stating explicitly to the team: the absence of an override is not
a missing feature, and "we have no override path" is a legitimate, recorded
answer. What is *not* acceptable is a repo that believes it has an override and
discovers at 2am that it never had an approver entry.

On a **fork** PR, GitHub withholds secrets and OIDC tokens entirely, so
break-glass fails closed there regardless of configuration.

---

## Part 4 — The rollout sequence **[REPO]**

Do not skip to enforcement. On a repo's first exposure to these scanners,
enforcement-first is the fastest way to get the pipeline disabled by the team —
and they will be right, because their first experience of it will be a wall of
findings they did not introduce.

| Phase | Setting | Leave when |
| --- | --- | --- |
| **1. Log-only** | `gate_mode: log-only` | you have seen a few real PRs' worth of findings |
| **2. Tune / baseline** | still `log-only` | the Semgrep baseline is committed from a **trusted** run, and rule noise is tuned |
| **3. Enforce on PRs** | `gate_mode: enforce`, `security-gate` required | the team is merging green without heroics for a week or two |
| **4. Enforce on main** | add the deploy-side gates | steady state |

Phase 2 is the one people skip, and it is the one that makes phase 3 survivable.

**Do not leave a repo in log-only after tuning.** The `gate-mode` check goes red
(without blocking the merge) whenever log-only is actually suppressing
something — a BLOCK that would otherwise have failed, or a scan whose integrity
could not be trusted. That red check is the signal that the repo has stopped
being "in rollout" and started being "unprotected".

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `not authorized to perform: sts:AssumeRoleWithWebIdentity` | The `sub` condition does not match. Print the real claims from the job. Check for a wildcard under `StringEquals` (§2.2). |
| `AccessDeniedException … inspector2:ListCoverage` | Enhanced scanning without the Inspector statement (§2.2). |
| The gate BLOCKs on a repo with no findings | Missing Semgrep baseline. A missing baseline is a fail-closed report-integrity BLOCK, not a pass (§1.1). |
| Deploy hangs, then fails | `ssm:GetCommandInvocation` scoped to the instance ARN. It must be `*` (§2.2). |
| `chat.postMessage` returns `not_in_channel` | The bot was never invited to the channel (§3.3). |
| Slack rejects the Request URL | The endpoint was not live when you saved it (§3.3). |
| Everything is green but nothing is enforced | `gate_mode: log-only`, or a required check that no longer matches by name (§1.6). |
