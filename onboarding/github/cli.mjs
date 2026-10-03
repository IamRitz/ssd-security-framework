// `ssd-onboard github …` — the Phase 2E trust boundary.
//
// Reached ONLY through a dynamic import from the `github` branch of cli.mjs,
// so no repository command's module graph contains the GitHub mutators. This
// side reads .ssd/onboarding.yml and talks to GitHub through gh-cli.mjs with
// the operator's own `gh` login; it never writes .ssd/onboarding.yml, never
// edits a workflow or any other repository file, and makes no AWS call.
//
//   plan --scope secrets|protection   READ-ONLY on GitHub; writes only
//                                     .ssd/github-plans/<plan-id>/plan.json
//   apply --plan-id <id> --slug <o/r> executes exactly that plan, once
//
// There is deliberately no `github protect`: changing merge governance needs
// the same reviewed plan / exact apply as everything else (D.8, D.14).
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { CONFIG_PATH, loadConfig } from '../lib/config.mjs';
import { detectFramework } from '../lib/framework.mjs';
import { inspectRepository } from '../lib/inspect.mjs';
import { terminalPrompter } from '../lib/prompt.mjs';
import { ApplyError, githubApply, exitCodeOf as applyExitCodeOf } from './apply.mjs';
import { GitHubDataError } from './discover.mjs';
import { GhCliError, SLUG } from './gh-cli.mjs';
import { SCOPES, githubPlan, exitCodeOf as planExitCodeOf } from './plan.mjs';
import { PLAN_ID, PlanRecordError } from './record.mjs';
import { githubApplyBlocks, githubApplyPreflightBlocks, githubErrorBlocks, githubErrorReport, githubPlanBlocks } from './report.mjs';
import { readSecret as readSecretInput } from './secret-input.mjs';

export const GITHUB_USAGE = `ssd-onboard github — GitHub configuration for the configured repository (Phase 2E)

Usage: node <framework>/onboarding/cli.mjs github <command> [options]

Authentication is your own GitHub CLI login (\`gh auth login\`) or GH_TOKEN.
ssd-onboard never reads, accepts or prints a token. Every command targets ONLY
repository.slug from .ssd/onboarding.yml, and refuses when GitHub or the local
origin names another repository or default branch.

  plan --scope secrets|protection [--json]
                          READ-ONLY on GitHub. Inspects the repository and records what
                          would change in .ssd/github-plans/<plan-id>/plan.json (its only
                          write). Never reads a secret value (GitHub cannot return one).
                          secrets: the Slack webhook secret named by
                            notifications.slack.githubSecretName (only when Slack is
                            enabled): absent -> create, present (value unknowable) -> rotate.
                          protection: proves, for the default branch, a pull request with
                            code-owner review, >= 1 approval, stale approvals dismissed and
                            the last push approved; the required check \`security-gate\`
                            from GitHub Actions (exact name, pinned app); no bypass; and a
                            CODEOWNERS file GitHub accepts. Proposes at most ONE new ruleset
                            with only the missing rules; never edits an existing ruleset or
                            classic branch protection.
                          Exit 0 planned / compliant / nothing to change,
                          1 incomplete / not verified / blocked / error
  apply --plan-id <id> --slug <owner/repo> [--yes] [--json]
                          Executes EXACTLY the recorded plan, once, after re-verifying the
                          plan record, configuration, framework ref, repository identity and
                          the live GitHub state it was derived from. Asks you to TYPE the
                          repository; --yes skips only that. A secrets plan then reads the
                          webhook from a hidden prompt, or from stdin when stdin is not a
                          terminal (then --yes is required); the value goes to
                          \`gh secret set\` on stdin only and is never stored or printed.
                          Exit 0 applied, 1 refused / error / apply failed

Options:
  --repo <dir>            consumer repository root (default: current directory)
  --scope secrets|protection
                          plan only (required)
  --plan-id <id>          apply only: the 64-hex plan id printed by github plan
  --slug <owner/repo>     apply only: must equal repository.slug
  --yes                   apply only: no typed confirmation (--slug is still required)
  --json                  one machine-readable JSON document (schemaVersion 1)
  -h, --help
`;

const OPTIONS = {
  repo: { type: 'string' },
  scope: { type: 'string' },
  'plan-id': { type: 'string' },
  slug: { type: 'string' },
  yes: { type: 'boolean' },
  json: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' }
};

class GithubUsageError extends Error {}

// Run-ending failures, reported as ERROR (exit 1). Nothing on GitHub was
// changed when one of these is thrown.
const RUN_ERRORS = [GhCliError, GitHubDataError, PlanRecordError, ApplyError];
const isRunError = (error) => RUN_ERRORS.some((type) => error instanceof type) || error?.name === 'PathConfinementError' || error?.kind === 'configuration';

function usage(context, message) {
  context.err(`${message}\n\n${GITHUB_USAGE}`);
  return 2;
}

async function loadRepositoryConfig(root) {
  let loaded;
  try {
    loaded = await loadConfig(join(root, CONFIG_PATH));
  } catch (error) {
    error.kind = 'configuration';
    throw error;
  }
  const { config, errors } = loaded;
  if (!config || errors.length > 0) {
    const error = new Error(`${CONFIG_PATH} is invalid (run \`ssd-onboard validate\`): ${errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`);
    error.kind = 'configuration';
    throw error;
  }
  return config;
}

export async function githubMain(args, context) {
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (error) {
    return usage(context, error.message);
  }
  const [sub, ...extra] = positionals;
  if (values.help || sub === 'help') {
    context.out(GITHUB_USAGE);
    return 0;
  }
  if (!sub) {
    return usage(context, 'missing github command');
  }
  try {
    if (extra.length > 0) {
      throw new GithubUsageError(`unexpected argument '${extra[0]}'`);
    }
    const root = resolve(values.repo ?? process.cwd());
    switch (sub) {
      case 'plan':
        for (const name of ['plan-id', 'slug', 'yes']) {
          if (values[name] !== undefined) throw new GithubUsageError(`Unknown option '--${name}' (apply only)`);
        }
        if (!SCOPES.includes(values.scope)) {
          throw new GithubUsageError(`github plan requires --scope secrets|protection${values.scope ? ` (got '${values.scope}')` : ''}: one plan holds one privilege class`);
        }
        return await cmdPlan(root, values, context);
      case 'apply':
        if (values.scope !== undefined) {
          throw new GithubUsageError("Unknown option '--scope' (a plan already names its scope)");
        }
        if (values['plan-id'] === undefined || values.slug === undefined) {
          throw new GithubUsageError(`github apply requires --plan-id and --slug${values.yes ? ': --yes never stands in for the repository you intend to change' : ''}`);
        }
        if (!PLAN_ID.test(values['plan-id'])) {
          throw new GithubUsageError(`--plan-id '${values['plan-id']}' is not a plan id (64 lower-case hex characters)`);
        }
        if (!SLUG.test(values.slug)) {
          throw new GithubUsageError(`--slug '${values.slug}' is not an owner/repository name`);
        }
        return await cmdApply(root, values, context);
      case 'protect':
        throw new GithubUsageError("there is no 'github protect': use `github plan --scope protection`, review it, then `github apply --plan-id <id> --slug <owner/repo>`");
      default:
        throw new GithubUsageError(`unknown github command '${sub}'`);
    }
  } catch (error) {
    if (error instanceof GithubUsageError) {
      return usage(context, error.message);
    }
    throw error;
  }
}

async function cmdPlan(root, options, context) {
  const scope = options.scope;
  let slug = null;
  const fail = (error) => {
    const report = githubErrorReport(error, { command: 'github plan', scope, slug });
    if (options.json) context.json(report);
    else context.printErr(githubErrorBlocks(report));
    return 1;
  };
  try {
    const config = await loadRepositoryConfig(root);
    slug = config.repository.slug;
    const facts = context.githubFacts ?? (await inspectRepository(root));
    const framework = context.framework !== undefined ? context.framework : await detectFramework();
    const report = await githubPlan({ config, facts, scope, framework, root, exec: context.ghExec, env: context.env ?? process.env, now: context.now });
    if (options.json) context.json(report);
    else context.print(githubPlanBlocks(report));
    return planExitCodeOf(report);
  } catch (error) {
    if (isRunError(error)) return fail(error);
    throw error;
  }
}

async function cmdApply(root, options, context) {
  const planId = options['plan-id'];
  let slug = null;
  const fail = (error) => {
    const report = githubErrorReport(error, { command: 'github apply', planId, slug });
    if (options.json) context.json(report);
    else context.printErr(githubErrorBlocks(report));
    return 1;
  };
  const stdin = context.stdin ?? process.stdin;
  // Typed confirmation needs a terminal (or an injected prompter). When stdin
  // carries the secret it cannot also carry a confirmation: --yes is required.
  let prompter = null;
  const confirm = options.yes
    ? null
    : context.prompter || stdin.isTTY
      ? async ({ slug: target }) => {
          prompter = context.prompter ?? terminalPrompter();
          try {
            return await prompter.ask({ id: 'confirmRepository', question: `Type ${target} to change it` });
          } finally {
            prompter.close();
            prompter = null;
          }
        }
      : null;
  const readSecret = context.readSecret ?? (() => readSecretInput({ input: stdin, output: process.stderr }));
  let preflightShown = false;
  try {
    const config = await loadRepositoryConfig(root);
    slug = config.repository.slug;
    const facts = context.githubFacts ?? (await inspectRepository(root));
    const framework = context.framework !== undefined ? context.framework : await detectFramework();
    const report = await githubApply({
      config,
      facts,
      planId,
      slug: options.slug,
      yes: options.yes === true,
      confirm,
      readSecret,
      framework,
      root,
      exec: context.ghExec,
      env: context.env ?? process.env,
      now: context.now,
      onPreflight: (r) => {
        if (!options.json) {
          context.print(githubApplyPreflightBlocks(r));
          preflightShown = true;
        }
      }
    });
    if (options.json) context.json(report);
    else context.print(githubApplyBlocks(report, { preflightShown }));
    return applyExitCodeOf(report);
  } catch (error) {
    if (isRunError(error)) return fail(error);
    throw error;
  } finally {
    prompter?.close();
  }
}
