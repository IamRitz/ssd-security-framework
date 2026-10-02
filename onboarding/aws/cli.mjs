// `ssd-onboard aws …` — the Phase 2 trust boundary.
//
// Reached ONLY through a dynamic import from the `aws` branch of cli.mjs, so no
// repository command's module graph contains the AWS executor. This side reads
// .ssd/onboarding.yml and talks to AWS with the operator's ambient AWS CLI
// credentials; it never writes .ssd/onboarding.yml and makes no GitHub call.
//
// Phase 2A implements `aws doctor` (read-only); Phase 2B implements `aws plan`
// (unexecuted change sets + .ssd/aws-plans/, its ONLY repository write);
// Phase 2C implements `aws apply` (executes exactly one recorded change set;
// writes only apply-started.json / apply.json into that plan's directory).
// verify is designed (docs/onboarding-architecture.md Part D) and not
// implemented.
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { CONFIG_PATH, isEcrProfile, loadConfig } from '../lib/config.mjs';
import { AwsCliError, execAws } from './aws-cli.mjs';
import { awsDoctor, exitCodeOf } from './doctor.mjs';
import { IdentityError, REGION } from './identity.mjs';
import { awsDoctorBlocks, awsErrorBlocks, awsErrorReport } from './report.mjs';
import { awsPlan, exitCodeOf as planExitCodeOf, SCOPES } from './plan.mjs';
import { awsPlanBlocks, awsPlanErrorBlocks, awsPlanErrorReport } from './plan-report.mjs';
import { awsApply, exitCodeOf as applyExitCodeOf } from './apply.mjs';
import { awsApplyBlocks, awsApplyErrorBlocks, awsApplyErrorReport, awsApplyPreflightBlocks, executingBlocks } from './apply-report.mjs';
import { PLAN_ID } from './plan/record.mjs';
import { detectFramework } from '../lib/framework.mjs';
import { terminalPrompter } from '../lib/prompt.mjs';

export const AWS_USAGE = `ssd-onboard aws — AWS readiness for the configured delivery (Phase 2)

Usage: node <framework>/onboarding/cli.mjs aws <command> [options]

Credentials come only from the AWS CLI's own provider chain (AWS_PROFILE, SSO,
instance/role credentials…). ssd-onboard never reads, accepts or prints a key.

  doctor [--region <r>] [--json]
                          READ-ONLY: caller identity, account and region, GitHub OIDC
                          provider, ECR repository and registry scanning, role trust and
                          permissions, SSM instance, ownership. Makes no AWS change.
                          Exit 0 ready (warnings allowed), 1 blocked or not verifiable
  plan [--scope repo|shared] [--region <r>] [--json]
                          Creates an UNEXECUTED CloudFormation change set per stack and
                          records it in .ssd/aws-plans/<plan-id>/. Never executes it.
                          repo (default): the per-repository delivery stack (ECR repository,
                          push+scan and deploy roles — only those configured managed).
                          shared: the GitHub OIDC provider stack (when managed); registry
                          scanning and Inspector are reported, never planned.
                          A CREATE change set leaves a REVIEW_IN_PROGRESS placeholder stack.
                          Requires a clean framework checkout at framework.ref.
                          Exit 0 planned / no changes / nothing to plan, 1 blocked or error
  apply --plan-id <id> --account <12 digits> --region <r>
        [--allow-destructive <n>] [--yes] [--json]
                          Executes EXACTLY the change set recorded in .ssd/aws-plans/<id>/,
                          once, after re-verifying the plan hashes, caller, account, region,
                          configuration, framework binding, the live change set and template,
                          and the stack (UPDATE: unchanged base revision; CREATE: the recorded
                          REVIEW_IN_PROGRESS placeholder). Asks you to TYPE the account id and
                          the region; --yes skips that only with both flags given. Destructive
                          changes (DELETE/REPLACE) need --allow-destructive <their exact count>.
                          Never edits .ssd/onboarding.yml or any repository file; writes only
                          apply-started.json / apply.json into the plan directory.
                          Exit 0 applied, 1 refused / error / apply failed
  verify                  designed (docs/onboarding-architecture.md Part D), not implemented

Options:
  --repo <dir>            consumer repository root (default: current directory)
  --region <r>            must equal delivery.aws.region when given; the AWS CLI's default
                          region is never used
  --scope repo|shared     plan only (default repo)
  --plan-id <id>          apply only: the 64-hex plan id printed by aws plan
  --account <id>          apply only: must equal the plan, delivery.aws.accountId and the caller
  --allow-destructive <n> apply only: the exact number of DELETE + REPLACE changes
  --yes                   apply only: no typed confirmation (requires --account and --region)
  --json                  one machine-readable JSON document (schemaVersion 1)
  -h, --help
`;

const OPTIONS = {
  repo: { type: 'string' },
  region: { type: 'string' },
  scope: { type: 'string' },
  'plan-id': { type: 'string' },
  account: { type: 'string' },
  'allow-destructive': { type: 'string' },
  yes: { type: 'boolean' },
  json: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' }
};

class AwsUsageError extends Error {}

const APPLY_ONLY = ['plan-id', 'account', 'allow-destructive', 'yes'];
const ACCOUNT_ID = /^\d{12}$/;

function usage(context, message) {
  context.err(`${message}\n\n${AWS_USAGE}`);
  return 2;
}

// args: everything after `aws`. context: cli.mjs channels plus injected io
// (awsExec for tests, env).
export async function awsMain(args, context) {
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (error) {
    return usage(context, error.message);
  }
  const [sub, ...extra] = positionals;
  if (values.help || sub === 'help') {
    context.out(AWS_USAGE);
    return 0;
  }
  if (!sub) {
    return usage(context, 'missing aws command');
  }
  try {
    if (extra.length > 0) {
      throw new AwsUsageError(`unexpected argument '${extra[0]}'`);
    }
    if (sub !== 'apply') {
      // apply's options are refused elsewhere rather than silently ignored.
      const stray = APPLY_ONLY.find((name) => values[name] !== undefined);
      if (stray) {
        throw new AwsUsageError(`Unknown option '--${stray}'`);
      }
    }
    switch (sub) {
      case 'doctor':
        if (values.scope !== undefined) {
          // Only plan takes --scope; doctor's options are unchanged.
          throw new AwsUsageError("Unknown option '--scope'");
        }
        return await cmdAwsDoctor(resolve(values.repo ?? process.cwd()), values, context);
      case 'plan':
        return await cmdAwsPlan(resolve(values.repo ?? process.cwd()), values, context);
      case 'apply':
        if (values.scope !== undefined) {
          throw new AwsUsageError("Unknown option '--scope' (a plan already names its scope)");
        }
        return await cmdAwsApply(resolve(values.repo ?? process.cwd()), values, context);
      case 'verify':
        context.err(
          "'ssd-onboard aws verify' is designed but not implemented in this version (Phase 2D).\n" +
            'Its reviewed design is in docs/onboarding-architecture.md Part D. Nothing was contacted.'
        );
        return 2;
      default:
        throw new AwsUsageError(`unknown aws command '${sub}'`);
    }
  } catch (error) {
    if (error instanceof AwsUsageError) {
      return usage(context, error.message);
    }
    throw error;
  }
}

function configurationError(message) {
  const error = new Error(message);
  error.kind = 'configuration';
  return error;
}

async function loadDelivery(root, command = 'aws doctor') {
  let loaded;
  try {
    loaded = await loadConfig(join(root, CONFIG_PATH));
  } catch (error) {
    throw configurationError(error.message);
  }
  const { config, errors } = loaded;
  if (!config || errors.length > 0) {
    throw configurationError(`${CONFIG_PATH} is invalid (run \`ssd-onboard validate\`): ${errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`);
  }
  if (!isEcrProfile(config.profile) || !config.delivery) {
    throw configurationError(
      command === 'aws doctor'
        ? `aws doctor checks the AWS delivery of the container-ecr-framework-gated profile; this repository's profile is ${config.profile} (no delivery.* to check)`
        : command === 'aws apply'
          ? `aws apply applies plans of the AWS delivery of the container-ecr-framework-gated profile; this repository's profile is ${config.profile} (no delivery.* to apply)`
          : `${command} plans the AWS delivery of the container-ecr-framework-gated profile; this repository's profile is ${config.profile} (no delivery.* to plan)`
    );
  }
  return config;
}

async function cmdAwsDoctor(root, options, context) {
  if (options.region !== undefined && !REGION.test(options.region)) {
    throw new AwsUsageError(`--region '${options.region}' is not an AWS region name`);
  }
  const fail = (error, target = null) => {
    const errorReport = awsErrorReport(error, target);
    if (options.json) {
      context.json(errorReport);
    } else {
      context.printErr(awsErrorBlocks(errorReport));
    }
    return 1;
  };
  let config;
  try {
    config = await loadDelivery(root);
  } catch (error) {
    return fail(error);
  }
  const target = { repository: config.repository.slug, account: config.delivery.aws.accountId, region: options.region ?? config.delivery.aws.region };
  let report;
  try {
    report = await awsDoctor({ config, region: options.region ?? null, exec: context.awsExec ?? execAws, env: context.env ?? process.env });
  } catch (error) {
    if (error instanceof AwsCliError || error instanceof IdentityError) {
      return fail(error, target);
    }
    throw error;
  }
  if (options.json) {
    context.json(report);
  } else {
    context.print(awsDoctorBlocks(report));
  }
  return exitCodeOf(report);
}

// Run-ending failures of `aws plan`: typed errors, reported as ERROR (exit 1).
const PLAN_ERRORS = new Set(['AwsCliError', 'IdentityError', 'PlanError', 'ChangeSetError', 'ScopeError', 'PlanRecordError', 'PathConfinementError', 'TrustBuildError']);

async function cmdAwsPlan(root, options, context) {
  if (options.region !== undefined && !REGION.test(options.region)) {
    throw new AwsUsageError(`--region '${options.region}' is not an AWS region name`);
  }
  const scope = options.scope ?? 'repo';
  if (!SCOPES.includes(scope)) {
    throw new AwsUsageError(`--scope must be repo or shared (got '${scope}')`);
  }
  const fail = (error, target = null) => {
    const errorReport = awsPlanErrorReport(error, target);
    if (options.json) {
      context.json(errorReport);
    } else {
      context.printErr(awsPlanErrorBlocks(errorReport));
    }
    return 1;
  };
  let config;
  try {
    config = await loadDelivery(root, 'aws plan');
  } catch (error) {
    return fail(error);
  }
  const target = { repository: config.repository.slug, account: config.delivery.aws.accountId, region: options.region ?? config.delivery.aws.region, scope };
  const framework = context.framework !== undefined ? context.framework : await detectFramework();
  let report;
  try {
    report = await awsPlan({ config, scope, region: options.region ?? null, exec: context.awsExec ?? execAws, env: context.env ?? process.env, framework, root, sleep: context.awsSleep });
  } catch (error) {
    if (PLAN_ERRORS.has(error?.name)) {
      return fail(error, target);
    }
    throw error;
  }
  if (options.json) {
    context.json(report);
  } else {
    context.print(awsPlanBlocks(report));
  }
  return planExitCodeOf(report);
}

// Run-ending failures of `aws apply` BEFORE execution: typed errors, reported
// as ERROR (exit 1). Nothing was executed when one of these is thrown.
const APPLY_ERRORS = new Set(['AwsCliError', 'IdentityError', 'ApplyError', 'PlanRecordError', 'PathConfinementError']);

async function cmdAwsApply(root, options, context) {
  const planId = options['plan-id'];
  if (planId === undefined || options.account === undefined || options.region === undefined) {
    throw new AwsUsageError(
      `aws apply requires --plan-id, --account and --region${options.yes ? ': --yes never stands in for them (the account and region you intend to change are always stated explicitly)' : ''}`
    );
  }
  if (!PLAN_ID.test(planId)) {
    throw new AwsUsageError(`--plan-id '${planId}' is not a plan id (64 lower-case hex characters)`);
  }
  if (!ACCOUNT_ID.test(options.account)) {
    throw new AwsUsageError(`--account '${options.account}' is not a 12-digit AWS account id`);
  }
  if (!REGION.test(options.region)) {
    throw new AwsUsageError(`--region '${options.region}' is not an AWS region name`);
  }
  const allow = options['allow-destructive'];
  if (allow !== undefined && !/^(?:0|[1-9]\d{0,5})$/.test(allow)) {
    throw new AwsUsageError(`--allow-destructive takes the exact number of destructive changes (got '${allow}')`);
  }
  const target = { repository: null, account: options.account, region: options.region, planId };
  const fail = (error) => {
    const errorReport = awsApplyErrorReport(error, target);
    if (options.json) {
      context.json(errorReport);
    } else {
      context.printErr(awsApplyErrorBlocks(errorReport));
    }
    return 1;
  };
  let config;
  try {
    config = await loadDelivery(root, 'aws apply');
  } catch (error) {
    return fail(error);
  }
  target.repository = config.repository.slug;
  const framework = context.framework !== undefined ? context.framework : await detectFramework();

  // Typed confirmation: an injected prompter (tests) or a terminal. Without
  // either, and without --yes, apply refuses before contacting AWS.
  let prompter = null;
  const confirm = options.yes
    ? null
    : context.prompter || process.stdin.isTTY
      ? async ({ account, region }) => {
          prompter = context.prompter ?? terminalPrompter();
          const typedAccount = await prompter.ask({ id: 'confirmAccount', question: `Type AWS account ${account} to continue` });
          if (typedAccount !== account) {
            return { account: typedAccount, region: null };
          }
          const typedRegion = await prompter.ask({ id: 'confirmRegion', question: `Type region ${region} to continue` });
          return { account: typedAccount, region: typedRegion };
        }
      : null;
  let preflightShown = false;
  let report;
  try {
    report = await awsApply({
      config,
      planId,
      account: options.account,
      region: options.region,
      yes: options.yes === true,
      allowDestructive: allow === undefined ? null : Number(allow),
      confirm,
      onPreflight: (r) => {
        if (!options.json) {
          context.print(awsApplyPreflightBlocks(r));
          preflightShown = true;
        }
      },
      onExecute: () => {
        if (!options.json) {
          context.print(executingBlocks());
        }
      },
      exec: context.awsExec ?? execAws,
      env: context.env ?? process.env,
      framework,
      root,
      sleep: context.awsSleep,
      waitMs: context.awsWaitMs
    });
  } catch (error) {
    if (APPLY_ERRORS.has(error?.name)) {
      return fail(error);
    }
    throw error;
  } finally {
    prompter?.close();
  }
  if (options.json) {
    context.json(report);
  } else {
    context.print(awsApplyBlocks(report, { preflightShown }));
  }
  return applyExitCodeOf(report);
}
