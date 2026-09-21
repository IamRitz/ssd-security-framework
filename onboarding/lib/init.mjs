// `init`: turns repository facts plus the owner's decisions into a config.
//
// The tool derives what it can prove from the checkout and ASKS only what the
// repository owner can answer. Where a wrong guess would silently weaken a
// control, it refuses to guess: a default branch it cannot read, a profile, an
// existing Gitleaks config or TruffleHog exclude file, an existing baseline.
import { posix } from 'node:path';

import {
  DEFAULT_FRAMEWORK_REPOSITORY,
  PROFILES,
  SCHEMA_VERSION,
  isContainerProfile,
  isEcrProfile
} from './config.mjs';

const DEFAULT_BASELINE = 'security/baseline/semgrep-baseline.json';

function imageNameFrom(slug) {
  const name = (slug ?? '').split('/').pop() ?? '';
  const cleaned = name.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[._-]+|[._-]+$/g, '');
  return cleaned || null;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function merge(base, override) {
  if (!isObject(base) || !isObject(override)) {
    return override === undefined ? base : override;
  }
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = isObject(value) && isObject(base[key]) ? merge(base[key], value) : value;
  }
  return out;
}

// Returns { config, decisions } where `decisions` lists owner decisions the
// partial did not make and that must not be defaulted.
export async function buildConfig(partial, facts) {
  const decisions = [];
  const p = partial ?? {};
  const has = (path) => path.split('.').reduce((node, key) => (isObject(node) && Object.hasOwn(node, key) ? node[key] : undefined), p) !== undefined;

  const profile = p.profile;
  if (!profile) {
    decisions.push(`profile: one of ${PROFILES.join(' | ')}`);
  }
  if (!has('repository.defaultBranch') && !facts.git.defaultBranch) {
    decisions.push('repository.defaultBranch: origin/HEAD is not set, and a wrong branch means pull requests are never scanned');
  }
  if (!has('repository.slug') && !facts.git.slug) {
    decisions.push('repository.slug: no GitHub origin remote to derive it from');
  }
  if (!has('framework.ref')) {
    decisions.push('framework.ref: the exact 40-character framework commit SHA this ssd-onboard checkout is at');
  }
  if (facts.files.includes('.gitleaks.toml') && !has('gitleaks.mode')) {
    decisions.push(
      "gitleaks.mode: .gitleaks.toml exists. Choose 'existing' (it must contain [extend] useDefault = true) or 'managed' (ssd-onboard generates one preserving the default rules). Silently ignoring it would drop its rules"
    );
  }
  if (facts.files.includes('.trufflehog-exclude-paths.txt') && !has('trufflehog.excludePathsFile')) {
    decisions.push("trufflehog.excludePathsFile: .trufflehog-exclude-paths.txt exists. Set it to that path to keep using it, or '' to scan every path");
  }
  const baselinePath = p.semgrep?.baseline?.path ?? DEFAULT_BASELINE;
  if ((await facts.exists(baselinePath)) && !has('semgrep.baseline.state')) {
    decisions.push(`semgrep.baseline.state: ${baselinePath} already exists. Set 'accepted' to adopt it as this repository's reviewed baseline`);
  }

  const defaults = {
    schemaVersion: SCHEMA_VERSION,
    repository: { slug: facts.git.slug, defaultBranch: facts.git.defaultBranch },
    framework: { repository: DEFAULT_FRAMEWORK_REPOSITORY },
    profile,
    workflows: { security: '.github/workflows/security.yml', ...(isEcrProfile(profile) ? { delivery: '.github/workflows/deploy.yml' } : {}) },
    rollout: { gateMode: 'log-only' },
    semgrep: {
      rulesets: facts.rulesetSuggestion.rulesets,
      // Coverage first: the whole repository, and no exclusions until the
      // owner has seen and accepted them.
      roots: ['.'],
      ignore: { managed: true, patterns: [] },
      baseline: { path: DEFAULT_BASELINE, state: 'absent' }
    },
    gitleaks: { mode: 'default' },
    trufflehog: { excludePathsFile: '' },
    notifications: { slack: { enabled: false, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } },
    breakGlass: { mode: 'disabled' }
  };
  if (isContainerProfile(profile)) {
    defaults.container = {
      dockerfile: facts.dockerfiles.length === 1 ? facts.dockerfiles[0] : undefined,
      context: '.',
      imageName: imageNameFrom(p.repository?.slug ?? facts.git.slug)
    };
    if (facts.dockerfiles.length === 1 && facts.dockerfiles[0].includes('/')) {
      defaults.container.context = posix.dirname(facts.dockerfiles[0]);
    }
  }
  if (isEcrProfile(profile)) {
    const image = p.container?.imageName ?? defaults.container.imageName;
    defaults.delivery = {
      ecr: { repository: image, ownership: 'existing' },
      oidcProvider: 'existing',
      roles: { pushScanOwnership: 'existing', deployOwnership: 'existing' },
      ssm: { appPort: '3000', containerName: image }
    };
  }
  return { config: merge(defaults, p), decisions };
}

// --- the interview ------------------------------------------------------------------

const nonEmpty = (value) => (value.trim() === '' ? 'required' : null);
const splitList = (value) => value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);

export async function interview(prompter, facts, { cliRef = null } = {}) {
  const partial = { repository: {}, framework: {}, semgrep: { ignore: {}, baseline: {} } };
  const say = (text) => prompter.say(text);

  say('ssd-onboard init — answers are recorded in .ssd/onboarding.yml (non-secret).');
  say('Only identifiers and decisions are asked for. Never paste a credential here.\n');

  partial.repository.slug = await prompter.ask({ id: 'slug', question: 'GitHub repository (owner/name)', default: facts.git.slug ?? '', validate: nonEmpty });
  partial.repository.defaultBranch = await prompter.ask({
    id: 'defaultBranch',
    question: 'Default / release branch (pull requests into it are scanned)',
    default: facts.git.defaultBranch ?? '',
    validate: nonEmpty
  });
  partial.framework.ref = await prompter.ask({
    id: 'frameworkRef',
    question: 'Exact framework commit to pin (must be the commit this ssd-onboard runs from)',
    default: cliRef ?? '',
    validate: nonEmpty
  });

  const suggestedProfile = facts.dockerfiles.length > 0 ? 'container-self-managed' : 'source-only';
  partial.profile = await prompter.choose({
    id: 'profile',
    question: 'Profile',
    default: suggestedProfile,
    choices: [
      { value: 'source-only', help: 'no container: source scanning only, no cloud access' },
      { value: 'container-self-managed', help: 'builds a container; scanned before it leaves CI; you deploy it' },
      { value: 'container-ecr-framework-gated', help: 'the framework pushes to ECR, gates the digest and deploys over SSM' }
    ]
  });
  partial.workflows = {
    security: await prompter.ask({ id: 'securityWorkflow', question: 'Security workflow file', default: '.github/workflows/security.yml' })
  };
  if (isEcrProfile(partial.profile)) {
    partial.workflows.delivery = await prompter.ask({ id: 'deliveryWorkflow', question: 'Delivery workflow file', default: '.github/workflows/deploy.yml' });
  }

  // Semgrep
  const languages = facts.rulesetSuggestion.languages.map((entry) => `${entry.pack} (${entry.count} files)`).join(', ') || 'none detected';
  say(`\nDetected languages: ${languages}`);
  partial.semgrep.rulesets = splitList(
    await prompter.ask({ id: 'rulesets', question: 'Semgrep rulesets (space separated)', default: facts.rulesetSuggestion.rulesets.join(' '), validate: nonEmpty })
  );
  say('Semgrep scans `.` (the whole repository) unless you narrow it. Narrowing puts everything else OUTSIDE SAST coverage.');
  partial.semgrep.roots = splitList(await prompter.ask({ id: 'roots', question: 'Semgrep scan roots', default: '.', validate: nonEmpty }));
  const hasSemgrepignore = facts.semgrepignore !== null;
  if (hasSemgrepignore) {
    say(`\nA .semgrepignore already exists:\n${facts.semgrepignore.trim().split('\n').map((l) => `    ${l}`).join('\n')}`);
    partial.semgrep.ignore.managed = await prompter.confirm({
      id: 'manageSemgrepignore',
      question: 'Let ssd-onboard manage .semgrepignore from the config (its current patterns must be copied into semgrep.ignore.patterns)?',
      default: false
    });
  } else {
    say('\nThere is no .semgrepignore. Without one, Semgrep silently skips tests/, test/, build/, vendor/, node_modules/ …');
    say('ssd-onboard will generate an explicit one.');
    partial.semgrep.ignore.managed = true;
  }
  if (partial.semgrep.ignore.managed) {
    const patterns = [];
    if (hasSemgrepignore) {
      patterns.push(...facts.semgrepignore.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
    }
    if (facts.ignoreSuggestions.length > 0) {
      say('Suggested exclusions (generated, vendored or build output that exists in this repository):');
      facts.ignoreSuggestions.forEach((s) => say(`    ${s.pattern.padEnd(18)} ${s.count} file(s) — ${s.reason}`));
      const accept = await prompter.confirm({ id: 'acceptIgnoreSuggestions', question: 'Exclude these from SAST?', default: false });
      if (accept) {
        patterns.push(...facts.ignoreSuggestions.map((s) => s.pattern));
      }
    }
    partial.semgrep.ignore.patterns = [...new Set(patterns)];
  }

  // Baseline
  const baselinePath = await prompter.ask({ id: 'baselinePath', question: 'Semgrep baseline path', default: DEFAULT_BASELINE });
  partial.semgrep.baseline.path = baselinePath;
  if (await facts.exists(baselinePath)) {
    say(`${baselinePath} already exists.`);
    const adopt = await prompter.confirm({ id: 'adoptBaseline', question: "Adopt it as this repository's reviewed, accepted baseline?", default: false });
    partial.semgrep.baseline.state = adopt ? 'accepted' : 'absent';
    if (!adopt) {
      say(`Then ${baselinePath} must be removed in a reviewed pull request before bootstrap; validation will report it.`);
    }
  } else {
    partial.semgrep.baseline.state = 'absent';
  }
  if (partial.semgrep.baseline.state === 'accepted') {
    partial.rollout = {
      gateMode: await prompter.choose({
        id: 'gateMode',
        question: 'Initial gate mode',
        default: 'log-only',
        choices: [
          { value: 'log-only', help: 'report only (recommended first)' },
          { value: 'enforce', help: 'a BLOCK fails the required security-gate check' }
        ]
      })
    };
  } else {
    say('No accepted baseline yet, so the gate starts in log-only (enforce needs a reviewed baseline).');
    partial.rollout = { gateMode: 'log-only' };
  }

  // Gitleaks
  if (facts.files.includes('.gitleaks.toml')) {
    say('\n.gitleaks.toml exists. A config without `[extend] useDefault = true` REPLACES every built-in Gitleaks rule.');
    partial.gitleaks = {
      mode: await prompter.choose({
        id: 'gitleaksMode',
        question: 'How should it be used?',
        default: 'existing',
        choices: [
          { value: 'existing', help: 'keep the file (validation requires it to extend the default ruleset)' },
          { value: 'managed', help: 'ssd-onboard generates it; copy custom rules into gitleaks.customRules' },
          { value: 'default', help: 'ignore it and use the default ruleset' }
        ]
      }),
      path: '.gitleaks.toml'
    };
  } else {
    const custom = await prompter.confirm({ id: 'gitleaksCustom', question: '\nAdd consumer-specific Gitleaks rules (defaults are always kept)?', default: false });
    partial.gitleaks = custom ? { mode: 'managed', path: '.gitleaks.toml', customRules: [] } : { mode: 'default' };
    if (custom) {
      say('Add rules under gitleaks.customRules in .ssd/onboarding.yml, then run ssd-onboard render.');
    }
  }

  // TruffleHog
  const existingExclude = facts.files.includes('.trufflehog-exclude-paths.txt');
  if (existingExclude) {
    say('\n.trufflehog-exclude-paths.txt exists (newline-separated regexes of paths TruffleHog skips).');
  }
  partial.trufflehog = {
    excludePathsFile: await prompter.ask({
      id: 'trufflehogExclude',
      question: "TruffleHog exclude-paths file ('' = scan every path)",
      default: existingExclude ? '.trufflehog-exclude-paths.txt' : ''
    })
  };
  if (partial.trufflehog.excludePathsFile === "''") {
    partial.trufflehog.excludePathsFile = '';
  }

  // Container
  if (isContainerProfile(partial.profile)) {
    say(`\nDockerfiles found: ${facts.dockerfiles.join(', ') || 'none'}`);
    const dockerfile = await prompter.ask({ id: 'dockerfile', question: 'Dockerfile', default: facts.dockerfiles[0] ?? 'Dockerfile', validate: nonEmpty });
    partial.container = {
      dockerfile,
      context: await prompter.ask({ id: 'context', question: 'Build context', default: dockerfile.includes('/') ? posix.dirname(dockerfile) : '.' }),
      imageName: await prompter.ask({ id: 'imageName', question: 'Local image name', default: imageNameFrom(partial.repository.slug) ?? '' , validate: nonEmpty })
    };
    say('The build job passes no build arguments and holds no credentials.');
  }

  // Delivery
  if (isEcrProfile(partial.profile)) {
    say('\nECR/SSM delivery. Only identifiers are recorded; nothing is created or checked in AWS by this command.');
    const accountId = await prompter.ask({ id: 'awsAccountId', question: 'AWS account ID', validate: nonEmpty });
    const region = await prompter.ask({ id: 'awsRegion', question: 'AWS region', validate: nonEmpty });
    partial.delivery = {
      aws: { accountId, region },
      ecr: {
        repository: await prompter.ask({ id: 'ecrRepository', question: 'ECR repository name', default: partial.container.imageName }),
        ownership: await prompter.choose({
          id: 'ecrOwnership',
          question: 'ECR repository',
          default: 'existing',
          choices: [{ value: 'existing' }, { value: 'managed', help: 'created by ssd-onboard aws apply (Phase 2)' }]
        })
      },
      oidcProvider: await prompter.choose({
        id: 'oidcProvider',
        question: 'GitHub OIDC provider in the account',
        default: 'existing',
        choices: [{ value: 'existing' }, { value: 'managed', help: 'shared account resource; Phase 2' }]
      }),
      roles: {
        pushScanRoleArn: await prompter.ask({ id: 'pushScanRoleArn', question: 'Push+scan role ARN (ECR only)', validate: nonEmpty }),
        deployRoleArn: await prompter.ask({ id: 'deployRoleArn', question: 'Deploy role ARN (SSM only — must differ from the push role)', validate: nonEmpty })
      },
      ssm: {
        instanceId: await prompter.ask({ id: 'instanceId', question: 'Existing SSM-managed EC2 instance ID', validate: nonEmpty }),
        appPort: await prompter.ask({ id: 'appPort', question: 'Host port on the instance (container listens on 3000)', default: '3000' }),
        containerName: await prompter.ask({ id: 'containerName', question: 'Container name on the instance', default: partial.container.imageName })
      },
      environment: await prompter.ask({ id: 'environment', question: "GitHub environment for the deploy job ('' for none)", default: '' })
    };
  }

  // Notifications
  const slack = await prompter.confirm({ id: 'slack', question: '\nSend BLOCK alerts to Slack?', default: false });
  partial.notifications = { slack: { enabled: slack } };
  if (slack) {
    partial.notifications.slack.githubSecretName = await prompter.ask({
      id: 'slackSecretName',
      question: 'Name of the GitHub repository SECRET holding the webhook URL (the URL itself is never recorded)',
      default: 'SECURITY_NOTIFY_SLACK_URL'
    });
  }

  // Break-glass is not generated in Phase 1; see docs/onboarding-cli.md.
  say('\nBreak-glass: disabled. Phase 1 does not generate it (an eligible BLOCK stays blocked).');
  partial.breakGlass = { mode: 'disabled' };
  return partial;
}
