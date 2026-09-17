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

### 1.1 Bootstrap the first Semgrep baseline

**Start here on a brand-new repository.** Everything else in Part 1 assumes this
is done.

A repo that has never had SAST has a backlog. Turn on a blocking gate cold and
the first PR fails on hundreds of pre-existing findings its author did not write
— and the team's correct conclusion is that the tool is broken. The baseline
records the current state as *known*, so the gate blocks only what a change
**introduces**.

#### Why a new repo needs an explicit bootstrap

You cannot simply "generate one first", because the two halves deadlock:

```
no baseline -> the source gate reports a report-integrity BLOCK
            -> integrity.trusted = false
            -> generate-semgrep-baseline.mjs refuses (correctly)
            -> no baseline can ever be produced
```

The generator's refusal is not a bug to work around. A scan whose input could
not be interpreted reports zero findings because it understood nothing, and
baselining that writes "no findings" into permanently accepted state.

`bootstrap_baseline` breaks the deadlock without relaxing that: it makes a
**missing** baseline an expected condition for one explicitly-requested run,
while every scanner-integrity check stays exactly as strict.

#### Run it once

1. Add the caller workflow (§1.2) with `gate_mode: log-only`.
2. Set the repository variable **`BOOTSTRAP_BASELINE=true`**
   (the source-only example already wires this to the `bootstrap_baseline`
   input; add the same line to any other caller).
3. Run the workflow — open a PR, or dispatch it.
4. Download the **`security-gate-results`** artifact from that run.
5. **Review `semgrep-baseline.candidate.json`.** This is the set of findings the
   repository is about to formally accept. Read it; do not rubber-stamp it.
6. Commit it as `security/baseline/semgrep-baseline.json`
   (or whatever `semgrep_baseline_path` says).
7. **Unset `BOOTSTRAP_BASELINE`.** Leaving it set is caught anyway — see below —
   but the variable should not linger.

From here the gate runs normally: your accepted findings log, and anything new
blocks. Proceed to §1.5 and the rollout in Part 4.

#### What bootstrap does NOT relax

Exactly one thing changes: a **missing** baseline stops being an integrity
failure, and SAST findings are evaluated against an empty accepted set and
reported with `baselineState: "unbaselined"` — reported, not waved through.

Everything that makes a scan trustworthy still applies:

| Still enforced during bootstrap | Consequence if it fails |
| --- | --- |
| The Semgrep report must parse | integrity BLOCK; no baseline generated |
| It must match the expected schema | integrity BLOCK; no baseline generated |
| It must carry **zero scan errors** | integrity BLOCK — a scan that did not finish looking is not a clean scan |
| The report must exist at all | integrity BLOCK |
| Every other scanner is evaluated normally | a malformed OSV or npm report still makes the whole run untrusted |
| The run must end `integrity.trusted: true` | the generator refuses, and the job **fails loudly** rather than silently producing nothing |

That last row matters in `log-only`, where nothing else fails: a bootstrap run
that could not produce a baseline is an explicit job failure, not a green run
with a missing artifact.

#### Bootstrap refuses to run twice

If a baseline **already exists** at `semgrep_baseline_path`, bootstrap fails:

```
bootstrap refused: a Semgrep baseline already exists at <path>. Baseline
bootstrap is for first onboarding only.
```

This is deliberate, and it is the reason bootstrap is an explicit input rather
than an automatic fallback. Two situations look identical on disk:

- **A.** a first onboarding, where no baseline exists yet, and
- **B.** an onboarded repository whose baseline was deleted or lost.

Auto-detecting "baseline missing ⇒ bootstrap" would make **B** silently
re-accept every finding the missing baseline used to gate. So **B keeps failing
closed**, and the only way to get bootstrap behaviour is to ask for it, in a way
that is visible in the workflow run and in the gate result
(`bootstrap: { active: true, reason: … }`).

If you genuinely need to rebuild a baseline, delete the old one in a reviewed
pull request — where a CODEOWNER can see it (§1.4) — and then bootstrap.

#### Generating locally instead

The CI route above is the supported one, because it uses the same scanners and
the same integrity checks the gate uses. If you must do it by hand, the
generator takes the gate result as evidence and will refuse without it:

```sh
node <toolkit>/security/scripts/generate-semgrep-baseline.mjs \
  --report reports/semgrep.json \
  --gate reports/security-gate.json \
  --rulesets "p/owasp-top-ten p/javascript" \
  --output security/baseline/semgrep-baseline.json
```

A run that produced `reports/DO-NOT-BASELINE.txt` must never be used.

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

You also declare the **phase** each caller runs in: `pr` for pull requests and
the scheduled sweep, `delivery` for the push-to-main run that publishes and
deploys. The conformance report then answers two separate questions:

1. *What security controls does this repository require?* — every control marked
   `appliesToRepository`.
2. *Which required controls actually executed successfully in this run?* — every
   control with status `applied`.

Each control resolves to exactly one of five outcomes, and the distinctions are
the entire point:

- **applied** — ran in this phase, with a real result recorded.
- **deferred** — required by this repository, but does not run in *this* phase.
  A pull request cannot execute a deploy, so the deploy control is `deferred`
  there and proven by the delivery run. It is never reported as a pass.
- **N/A** — a stable fact about what this repo is. A library has no image.
- **exempt** — a control that *applies*, deliberately not enforced. It is debt:
  it needs an owner and an expiry, and it expires closed.
- **failed** — applies, was expected now, and did not pass. A control that
  applies and produced no evidence at all is `failed`, never absent: absence of
  evidence is not evidence a control ran.

A caller that hard-codes `"gated-deploy": {"status": "pass"}` on a pull request
does not get a pass — the control is still reported `deferred`, and the report
carries a warning that a control which did not execute cannot have passed.

**Feed conformance per-control evidence, never the aggregate.** Copy the `observed`
block from your example as-is. It reads each source control from its own output of
`_source-security.yml`:

```yaml
observed: >-
  {"secret-scan":{"status":"${{ needs.source-security.outputs.secret_scan_result }}","evidence":"Secret scanning job (per-control output)"},
   "dependency-scan":{"status":"${{ needs.source-security.outputs.dependency_scan_result }}","evidence":"Dependency scanning job (per-control output)"},
   "sast":{"status":"${{ needs.source-security.outputs.sast_result }}","evidence":"SAST job (per-control output)"},
   "source-gate":{"status":"${{ needs.source-security.outputs.source_gate_result }}","verdict":"${{ needs.source-security.outputs.verdict }}","gate_mode":"${{ needs.source-security.outputs.gate_mode }}","integrity_trusted":"${{ needs.source-security.outputs.integrity_trusted }}","evidence":"source-gate job"}}
```

Do **not** use `needs.source-security.result` for these four. It is the aggregate of
every job, so when the gate BLOCKs it is `failure` and all three scanners would be
reported failed although they ran. (That is exactly what a live Python consumer
saw: four failures for three working scanners and one policy BLOCK.)

Read the source controls as two different questions:

- **A scanning control** (secret scanning, dependency scanning, SAST) asks *did the
  scanner execute and produce trustworthy evidence?* `applied` means a usable report
  was produced — **not** that no vulnerabilities were found. A scanner that finds
  vulnerabilities is applied. It fails only when there is no trustworthy report: the
  job failed, was cancelled or skipped, or the gate could not interpret its report
  (`untrusted`).
- **The source security gate** asks *did that evidence satisfy security policy?* A
  BLOCK fails this control, with the reason spelled out (*the source security policy
  gate returned a blocking result*, or *failed closed: a scan report could not be
  trusted*).

A finding is not a scanner failure. The dependency scanning job may show a blue
notice such as *pip-audit exited 1 (vulnerabilities found) with a valid report* —
that is a working scan, not an error.

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

The log-only warnings depend on the verdict, so they stay honest:

- **PASS in log-only** — *Security gate verdict: PASS. gate_mode=log-only; no blocking
  verdict exists, so nothing was suppressed.* There was nothing to enforce; the
  warning is only a reminder that the repository is still in rollout mode.
- **BLOCK in log-only** — *Security gate verdict: BLOCK, but gate_mode=log-only so the
  BLOCK is reported and NOT enforced*, and the `security-gate` aggregate says
  **GREEN BY CONFIGURATION, not by verdict**. This is the one to act on.

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

Three caveats worth knowing:

- **`security-gate` must represent every control that gates the PR.** For a
  container repository that is source security **and** the pre-push image gate.
  The shipped examples aggregate both: a PR whose image gate reported
  `BLOCK_DEPLOY` fails the check, because the name promises "this PR is secure"
  and has to mean it. A source-only repo has no image control to aggregate, so
  its aggregate is source-only. Requiring a check that covers only half the
  controls is worse than requiring none, because it looks like coverage.
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
| **0. Bootstrap** | `gate_mode: log-only` + `bootstrap_baseline: true`, once | the candidate baseline is reviewed and committed, and the variable is unset (§1.1) |
| **1. Log-only** | `gate_mode: log-only` | you have seen a few real PRs' worth of findings |
| **2. Tune / baseline** | still `log-only` | rule noise is tuned and the baseline is regenerated from a **trusted** run if needed |
| **3. Enforce on PRs** | `gate_mode: enforce`, `security-gate` required | the team is merging green without heroics for a week or two |
| **4. Enforce on main** | add the delivery caller (`deploy.yml`) and its gates | steady state |

Phase 2 is the one people skip, and it is the one that makes phase 3 survivable.

Phase 4 is where the `delivery` phase starts being proven: until then a
container repo's conformance report honestly shows the registry, artifact-gate
and deploy controls as **deferred** — required, not yet demonstrated.

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
| The gate BLOCKs on a repo with no findings | Missing Semgrep baseline. A missing baseline is a fail-closed report-integrity BLOCK, not a pass. Bootstrap it (§1.1). |
| `bootstrap refused: a Semgrep baseline already exists` | Bootstrap is for first onboarding only. If the baseline genuinely needs rebuilding, delete it in a reviewed PR first (§1.1). |
| `Baseline bootstrap FAILED: this run's scans could not be trusted` | A scanner could not interpret its input, so nothing may be baselined from it. Fix the scanner failure reported above it (§1.1). |
| Bootstrap ran but no candidate appeared | It refuses outside `gate_mode: log-only`, and refuses when a baseline exists (§1.1). |
| A container PR merged with a failing image gate | The required check aggregated only source security. Use the shipped example's `security-gate` job, which aggregates both (§1.6). |
| Conformance shows `deferred` controls | Correct on a pull request: those controls run in the `delivery` phase. They are required, and proven by the `deploy.yml` run (§1.3). |
| Conformance reports secret scanning, dependency scanning **and** SAST failed whenever the gate BLOCKs | The caller feeds `needs.source-security.result` (the aggregate) to every source control. Use the per-control outputs `secret_scan_result`, `dependency_scan_result`, `sast_result`, `source_gate_result` (§1.3). |
| A source scanning control is `untrusted` | The scanner job ran, but the gate could not interpret its report. Findings are UNKNOWN, not clean; see the integrity failure in the gate summary and never baseline from the run. |
| The dependency scanning job fails with `SCANNER RUN INVALID` | The scanner's exit status and report disagree, the status was unexpected (e.g. OSV-Scanner 127), or the report is empty/malformed. A plain "vulnerabilities found" exit never fails this step. |
| The PR comment shows fewer findings than `security-gate.json` | Records from different scanners describing the same advisory for the same package (shared advisory ids/aliases) are shown as one issue. The comment says "N unique issues from M scanner findings"; every raw record is still listed inside the issue and kept in `findings`. |
| The comment says a dependency's "effective version is disputed" | The scanners (or a scanner and your `requirements.txt` pin) reported different versions of that package, e.g. pip-audit `idna 3.19` vs OSV-Scanner `idna 3.9.0`. The policy action is unchanged. Establish the version actually installed (lockfile, build, environment) before remediating; do not pin from the report. See [evidence-model.md](evidence-model.md). |
| A dependency's relationship is "unknown" although it is not in `requirements.txt` | By design. Absence from the manifest does not prove a package is transitive, and no scanner report the framework runs records dependency paths ([evidence-model.md](evidence-model.md)). |
| Deploy hangs, then fails | `ssm:GetCommandInvocation` scoped to the instance ARN. It must be `*` (§2.2). |
| `chat.postMessage` returns `not_in_channel` | The bot was never invited to the channel (§3.3). |
| Slack rejects the Request URL | The endpoint was not live when you saved it (§3.3). |
| Everything is green but nothing is enforced | `gate_mode: log-only`, or a required check that no longer matches by name (§1.6). |
