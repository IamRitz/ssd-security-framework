// .ssd/onboarding.yml — the consumer-owned, NON-SECRET source of truth that
// every generated workflow is rendered from.
//
// The schema is CLOSED: an unknown key is an error, not ignored, so a typo such
// as `gateMod: enforce` cannot silently leave a repository in log-only. It holds
// identifiers and decisions (ARNs, resource names, secret NAMES), never
// credentials — every string is checked for credential shapes on load AND
// before write (see assertNoSecretValues).
import { readFile } from 'node:fs/promises';

import { parseYaml, stringifyYaml } from './yaml.mjs';

export const CONFIG_PATH = '.ssd/onboarding.yml';
export const SCHEMA_VERSION = '1';
export const DEFAULT_FRAMEWORK_REPOSITORY = 'IamRitz/ssd-security-framework';

export const PROFILES = ['source-only', 'container-self-managed', 'container-ecr-framework-gated'];
export const GATE_MODES = ['log-only', 'enforce'];
export const BASELINE_STATES = ['absent', 'accepted'];
export const GITLEAKS_MODES = ['default', 'managed', 'existing'];
export const OWNERSHIP = ['existing', 'managed'];
// Break-glass is NOT supported by Phase 1 generation: there is no observed
// evidence the generator could feed conformance (see onboarding-architecture.md
// B.8), so only `disabled` is accepted.
export const BREAK_GLASS_MODES = ['disabled'];

export const CAPABILITIES_BY_PROFILE = {
  'source-only': { artifact_type: 'library', registry: 'none', deploy_target: 'none' },
  'container-self-managed': { artifact_type: 'container', registry: 'none', deploy_target: 'self-managed' },
  'container-ecr-framework-gated': { artifact_type: 'container', registry: 'ecr', deploy_target: 'framework-gated' }
};

export const isContainerProfile = (profile) => profile !== 'source-only';
export const isEcrProfile = (profile) => profile === 'container-ecr-framework-gated';

// --- credential detection ------------------------------------------------------

// Shapes of credential VALUES. ARNs, names and secret NAMES are configuration;
// these are not. A match anywhere in the config refuses the whole file.
const CREDENTIAL_SHAPES = [
  { name: 'AWS access key ID', pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/ },
  { name: 'AWS secret access key assignment', pattern: /aws_secret_access_key/i },
  { name: 'Slack token', pattern: /\bxox[abeoprs]-[A-Za-z0-9-]{8,}/ },
  { name: 'Slack incoming-webhook URL', pattern: /hooks\.slack(?:-gov)?\.com\/(?:services|workflows|triggers)\//i },
  { name: 'GitHub token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})/ },
  { name: 'private key', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { name: 'URL with embedded credentials', pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i }
];

export function findSecretValues(value, path = '') {
  const hits = [];
  if (typeof value === 'string') {
    for (const shape of CREDENTIAL_SHAPES) {
      if (shape.pattern.test(value)) {
        hits.push({ path: path || '(root)', kind: shape.name });
      }
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, index) => hits.push(...findSecretValues(item, `${path}[${index}]`)));
  } else if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      hits.push(...findSecretValues(key, `${path}.${key}(key)`));
      hits.push(...findSecretValues(child, path ? `${path}.${key}` : key));
    }
  }
  return hits;
}

export class SecretValueError extends Error {
  constructor(hits) {
    super(
      'refusing a configuration that contains credential VALUES (this file is non-secret):\n' +
        hits.map((hit) => `  - ${hit.path}: looks like a ${hit.kind}`).join('\n') +
        '\nStore the value as a GitHub/AWS secret and record only its NAME or ARN.'
    );
    this.name = 'SecretValueError';
    this.hits = hits;
  }
}

export function assertNoSecretValues(value) {
  const hits = findSecretValues(value);
  if (hits.length > 0) {
    throw new SecretValueError(hits);
  }
}

// --- field validators --------------------------------------------------------

const RE = {
  slug: /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/,
  sha: /^[0-9a-f]{40}$/,
  branch: /^(?!-)(?!.*\.\.)(?!.*\/\/)(?!.*\/$)(?!.*\.lock$)[A-Za-z0-9._/-]{1,200}$/,
  workflowFile: /^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/,
  relPath: /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._@+\/-]+$/,
  ruleset: /^(?:p\/[a-z0-9][a-z0-9._-]*|r\/[A-Za-z0-9._-]+|(?!\/)(?!.*\.\.)[A-Za-z0-9._\/-]+\.ya?ml)$/,
  cron: /^(?:[0-9*,\/-]+ ){4}[0-9*,\/A-Za-z-]+$/,
  imageName: /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/,
  accountId: /^\d{12}$/,
  region: /^[a-z]{2}(?:-[a-z]+)+-\d$/,
  ecrRepository: /^(?=.{2,256}$)[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/,
  roleArn: /^arn:aws:iam::(\d{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*[A-Za-z0-9+=,.@_-]{1,64}$/,
  instanceId: /^i-[0-9a-f]{8,17}$/,
  containerName: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/,
  port: /^(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/,
  secretName: /^(?!GITHUB_)[A-Z_][A-Z0-9_]{0,99}$/,
  environmentName: /^[A-Za-z0-9_.-]{1,100}$/,
  digest: /^[0-9a-f]{64}$/,
  ruleId: /^[a-z0-9][a-z0-9-]{1,63}$/
};

// Catch-all patterns that would exclude everything (or nearly everything).
const CATCH_ALL = new Set(['*', '**', '**/*', '/', '.', './', '*/', '**/', '.*', '.+', '^', '$', '^.*$', '^.*', '.*$', '(.*)', '[\\s\\S]*']);

class Collector {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }
  error(path, message) {
    this.errors.push({ path, message });
  }
  warn(path, message) {
    this.warnings.push({ path, message });
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Reads a closed section: unknown keys are errors.
function section(c, raw, path, allowed, { required = true } = {}) {
  if (raw === undefined || raw === null) {
    if (required) {
      c.error(path, 'is required');
    }
    return null;
  }
  if (!isObject(raw)) {
    c.error(path, 'must be a mapping');
    return null;
  }
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) {
      c.error(`${path}.${key}`, `unknown key (allowed: ${allowed.join(', ')})`);
    }
  }
  return raw;
}

function str(c, raw, path, { re, required = true, allowEmpty = false, fallback, oneOf, hint } = {}) {
  let value = raw;
  if (value === undefined || value === null || (value === '' && !allowEmpty)) {
    if (fallback !== undefined) {
      return fallback;
    }
    if (required) {
      c.error(path, 'is required');
    }
    return allowEmpty ? '' : null;
  }
  if (typeof value !== 'string') {
    c.error(path, 'must be a string (quote it)');
    return null;
  }
  value = value.trim();
  if (value === '' && allowEmpty) {
    return '';
  }
  if (oneOf && !oneOf.includes(value)) {
    c.error(path, `'${value}' is not one of ${oneOf.join(' | ')}`);
    return null;
  }
  if (re && !re.test(value)) {
    c.error(path, `'${value}' is not valid${hint ? ` (${hint})` : ''}`);
    return null;
  }
  return value;
}

function bool(c, raw, path, fallback) {
  if (raw === undefined || raw === null) {
    return fallback;
  }
  if (typeof raw !== 'boolean') {
    c.error(path, 'must be true or false');
    return fallback;
  }
  return raw;
}

function list(c, raw, path, { required = false, nonEmpty = false } = {}) {
  if (raw === undefined || raw === null) {
    if (required) {
      c.error(path, 'is required');
    }
    return [];
  }
  if (!Array.isArray(raw)) {
    c.error(path, 'must be a list');
    return [];
  }
  if (nonEmpty && raw.length === 0) {
    c.error(path, 'must not be empty');
  }
  return raw;
}

function normalizeRelPath(value) {
  if (value === '.' || value === './') {
    return '.';
  }
  return value.replace(/^\.\//, '').replace(/\/+$/, '');
}

function regexProblem(source) {
  if (CATCH_ALL.has(source.trim())) {
    return 'matches everything';
  }
  try {
    const compiled = new RegExp(source);
    if (compiled.test('') && !/^\^/.test(source)) {
      return 'matches the empty string, so it matches every path';
    }
  } catch (error) {
    return `does not compile: ${error.message}`;
  }
  return null;
}

// --- the schema ----------------------------------------------------------------

export function validateConfig(raw, { today = new Date() } = {}) {
  const c = new Collector();
  const hits = findSecretValues(raw);
  for (const hit of hits) {
    c.error(hit.path, `looks like a ${hit.kind}; this file is non-secret — record the secret's NAME or ARN instead`);
  }

  const root = section(c, raw, 'config', [
    'schemaVersion', 'repository', 'framework', 'profile', 'workflows', 'rollout', 'semgrep', 'gitleaks',
    'trufflehog', 'container', 'delivery', 'notifications', 'breakGlass'
  ]);
  if (!root) {
    return { config: null, errors: c.errors, warnings: c.warnings };
  }

  const schemaVersion = String(root.schemaVersion ?? '');
  if (schemaVersion !== SCHEMA_VERSION) {
    c.error('schemaVersion', `must be '${SCHEMA_VERSION}' (got '${schemaVersion}'); refusing to guess at an unknown schema`);
  }

  const repositoryRaw = section(c, root.repository, 'repository', ['slug', 'defaultBranch']) ?? {};
  const repository = {
    slug: str(c, repositoryRaw.slug, 'repository.slug', { re: RE.slug, hint: 'owner/name' }),
    defaultBranch: str(c, repositoryRaw.defaultBranch, 'repository.defaultBranch', { re: RE.branch })
  };

  const frameworkRaw = section(c, root.framework, 'framework', ['repository', 'ref']) ?? {};
  const framework = {
    repository: str(c, frameworkRaw.repository, 'framework.repository', { re: RE.slug, fallback: DEFAULT_FRAMEWORK_REPOSITORY }),
    // An exact, immutable commit. Tags (even vX.Y.Z) can be moved, and the
    // generator validates its output against exactly this commit's reusable
    // workflow contracts (see framework.mjs), so nothing weaker is admitted.
    ref: str(c, frameworkRaw.ref, 'framework.ref', { re: RE.sha, hint: 'a full 40-character lowercase commit SHA; tags and branches move' })
  };

  const profile = str(c, root.profile, 'profile', { oneOf: PROFILES });

  const workflowsRaw = section(c, root.workflows, 'workflows', ['security', 'delivery']) ?? {};
  const workflows = {
    security: str(c, workflowsRaw.security, 'workflows.security', {
      re: RE.workflowFile,
      fallback: '.github/workflows/security.yml',
      hint: '.github/workflows/<name>.yml'
    })
  };
  if (isEcrProfile(profile)) {
    workflows.delivery = str(c, workflowsRaw.delivery, 'workflows.delivery', {
      re: RE.workflowFile,
      fallback: '.github/workflows/deploy.yml',
      hint: '.github/workflows/<name>.yml'
    });
    if (workflows.delivery && workflows.delivery === workflows.security) {
      c.error('workflows.delivery', 'must differ from workflows.security');
    }
  } else if (workflowsRaw.delivery !== undefined && workflowsRaw.delivery !== null) {
    c.error('workflows.delivery', `only the container-ecr-framework-gated profile has a delivery workflow (profile is ${profile})`);
  }
  for (const [key, file] of Object.entries(workflows)) {
    if (file && /\/_[^/]*$/.test(file)) {
      c.error(`workflows.${key}`, 'must not start with "_" — that prefix marks the framework\'s reusable workflows');
    }
  }

  const rolloutRaw = section(c, root.rollout, 'rollout', ['gateMode', 'schedule']) ?? {};
  const rollout = {
    gateMode: str(c, rolloutRaw.gateMode, 'rollout.gateMode', { oneOf: GATE_MODES, fallback: 'log-only' }),
    schedule: str(c, rolloutRaw.schedule, 'rollout.schedule', { re: RE.cron, fallback: '0 6 * * 1', hint: '5-field cron' })
  };

  const semgrepRaw = section(c, root.semgrep, 'semgrep', ['rulesets', 'roots', 'ignore', 'baseline']) ?? {};
  const rulesets = list(c, semgrepRaw.rulesets, 'semgrep.rulesets', { required: true, nonEmpty: true })
    .map((value, index) => str(c, value, `semgrep.rulesets[${index}]`, { re: RE.ruleset, hint: 'p/<pack>, r/<rule> or a local .yml path' }))
    .filter(Boolean);
  if (new Set(rulesets).size !== rulesets.length) {
    c.error('semgrep.rulesets', 'contains duplicates');
  }
  if (rulesets.length > 0 && rulesets.every((ruleset) => ruleset === 'p/owasp-top-ten')) {
    c.warn(
      'semgrep.rulesets',
      'only p/owasp-top-ten is configured. Add the language pack(s) for this repository — a ruleset for the wrong ' +
        'language (or none) reports near-zero findings, which reads as a clean pass'
    );
  }
  const roots = list(c, semgrepRaw.roots ?? ['.'], 'semgrep.roots', { nonEmpty: true })
    .map((value, index) => str(c, value, `semgrep.roots[${index}]`, { re: RE.relPath, hint: 'relative path without spaces or ..' }))
    .filter(Boolean)
    .map(normalizeRelPath);
  if (new Set(roots).size !== roots.length) {
    c.error('semgrep.roots', 'contains duplicates');
  }
  if (roots.includes('.') && roots.length > 1) {
    c.error('semgrep.roots', "'.' already covers the whole repository; remove the other roots");
  }
  const ignoreRaw = section(c, semgrepRaw.ignore, 'semgrep.ignore', ['managed', 'patterns'], { required: false }) ?? {};
  const ignore = {
    managed: bool(c, ignoreRaw.managed, 'semgrep.ignore.managed', true),
    patterns: list(c, ignoreRaw.patterns, 'semgrep.ignore.patterns')
      .map((value, index) => str(c, value, `semgrep.ignore.patterns[${index}]`))
      .filter(Boolean)
  };
  for (const [index, pattern] of ignore.patterns.entries()) {
    const path = `semgrep.ignore.patterns[${index}]`;
    const bare = pattern.replace(/^!/, '');
    if (CATCH_ALL.has(bare) || /^\/?\*\*?\/?$/.test(bare)) {
      c.error(path, `'${pattern}' excludes everything from SAST`);
    } else if (pattern.startsWith(':')) {
      c.error(path, `'${pattern}': Semgrep ignore directives (such as :include) are not generated; list patterns explicitly`);
    } else if (/(^|\/)(tests?|spec|specs|__tests__|migrations?|infra|infrastructure|terraform|scripts?|config|deploy|\.github)(\/|$)|(^|\/)\*?_?test/i.test(bare)) {
      c.warn(path, `'${pattern}' excludes test, migration, infrastructure, script or configuration code from SAST. Keep it only if that is a deliberate, reviewed decision`);
    }
  }
  if (!ignore.managed && ignore.patterns.length > 0) {
    c.error('semgrep.ignore.patterns', 'patterns are only rendered when semgrep.ignore.managed is true; with a human-owned .semgrepignore, edit that file instead');
  }
  const baselineRaw = section(c, semgrepRaw.baseline, 'semgrep.baseline', ['path', 'state', 'acceptedScope'], { required: false }) ?? {};
  const baseline = {
    path: str(c, baselineRaw.path, 'semgrep.baseline.path', { re: RE.relPath, fallback: 'security/baseline/semgrep-baseline.json' }),
    state: str(c, baselineRaw.state, 'semgrep.baseline.state', { oneOf: BASELINE_STATES, fallback: 'absent' }),
    acceptedScope: str(c, baselineRaw.acceptedScope, 'semgrep.baseline.acceptedScope', { re: RE.digest, required: false, allowEmpty: true })
  };
  if (baseline.path && !baseline.path.endsWith('.json')) {
    c.error('semgrep.baseline.path', 'must be a .json file');
  }
  const semgrep = { rulesets, roots, ignore, baseline };

  const gitleaksRaw = section(c, root.gitleaks, 'gitleaks', ['mode', 'path', 'customRules', 'allowlists'], { required: false }) ?? {};
  const gitleaks = {
    mode: str(c, gitleaksRaw.mode, 'gitleaks.mode', { oneOf: GITLEAKS_MODES, fallback: 'default' })
  };
  if (gitleaks.mode === 'default') {
    for (const key of ['path', 'customRules', 'allowlists']) {
      if (gitleaksRaw[key] !== undefined && gitleaksRaw[key] !== null && !(Array.isArray(gitleaksRaw[key]) && gitleaksRaw[key].length === 0)) {
        c.error(`gitleaks.${key}`, 'is only used when gitleaks.mode is managed or existing');
      }
    }
  } else {
    gitleaks.path = str(c, gitleaksRaw.path, 'gitleaks.path', { re: RE.relPath, fallback: '.gitleaks.toml' });
  }
  if (gitleaks.mode === 'managed') {
    gitleaks.customRules = list(c, gitleaksRaw.customRules, 'gitleaks.customRules').map((rule, index) => {
      const path = `gitleaks.customRules[${index}]`;
      const r = section(c, rule, path, ['id', 'description', 'regex', 'keywords']) ?? {};
      const regex = str(c, r.regex, `${path}.regex`);
      if (regex) {
        const problem = regexProblem(regex);
        if (problem) {
          c.error(`${path}.regex`, problem);
        }
        if (regex.includes("'''")) {
          c.error(`${path}.regex`, "must not contain ''' (it is written as a TOML literal string)");
        }
      }
      return {
        id: str(c, r.id, `${path}.id`, { re: RE.ruleId, hint: 'lowercase-kebab' }),
        description: str(c, r.description, `${path}.description`),
        regex,
        keywords: list(c, r.keywords, `${path}.keywords`).map((k, i) => str(c, k, `${path}.keywords[${i}]`, { re: /^[A-Za-z0-9_.-]{2,64}$/ }))
      };
    });
    gitleaks.allowlists = list(c, gitleaksRaw.allowlists, 'gitleaks.allowlists').map((entry, index) => {
      const path = `gitleaks.allowlists[${index}]`;
      const a = section(c, entry, path, ['description', 'paths', 'regexes']) ?? {};
      const paths = list(c, a.paths, `${path}.paths`).map((p, i) => str(c, p, `${path}.paths[${i}]`));
      const regexes = list(c, a.regexes, `${path}.regexes`).map((p, i) => str(c, p, `${path}.regexes[${i}]`));
      if (paths.length + regexes.length === 0) {
        c.error(path, 'must list at least one path or regex');
      }
      for (const [i, value] of [...paths.map((p) => ['paths', p]), ...regexes.map((p) => ['regexes', p])].entries()) {
        const problem = value[1] ? regexProblem(value[1]) : null;
        if (problem) {
          c.error(`${path}.${value[0]}`, `'${value[1]}' ${problem} — a broad allowlist disables secret scanning`);
        }
        if (value[1]?.includes("'''")) {
          c.error(`${path}.${value[0]}[${i}]`, "must not contain '''");
        }
      }
      return { description: str(c, a.description, `${path}.description`), paths, regexes };
    });
    const ids = gitleaks.customRules.map((rule) => rule.id).filter(Boolean);
    if (new Set(ids).size !== ids.length) {
      c.error('gitleaks.customRules', 'rule ids must be unique');
    }
  } else if (gitleaks.mode === 'existing') {
    for (const key of ['customRules', 'allowlists']) {
      if (Array.isArray(gitleaksRaw[key]) && gitleaksRaw[key].length > 0) {
        c.error(`gitleaks.${key}`, 'is only rendered when gitleaks.mode is managed; edit the existing file instead');
      }
    }
  }

  const trufflehogRaw = section(c, root.trufflehog, 'trufflehog', ['excludePathsFile'], { required: false }) ?? {};
  const trufflehog = {
    excludePathsFile: str(c, trufflehogRaw.excludePathsFile, 'trufflehog.excludePathsFile', {
      re: RE.relPath,
      required: false,
      allowEmpty: true
    }) ?? ''
  };

  let container = null;
  if (isContainerProfile(profile)) {
    const containerRaw = section(c, root.container, 'container', ['dockerfile', 'context', 'imageName']) ?? {};
    container = {
      dockerfile: str(c, containerRaw.dockerfile, 'container.dockerfile', { re: RE.relPath, fallback: 'Dockerfile' }),
      context: normalizeRelPath(str(c, containerRaw.context, 'container.context', { re: RE.relPath, fallback: '.' }) ?? '.'),
      imageName: str(c, containerRaw.imageName, 'container.imageName', { re: RE.imageName, hint: 'lowercase docker repository name' })
    };
  } else if (root.container !== undefined && root.container !== null) {
    c.error('container', 'is only used by container profiles');
  }

  let delivery = null;
  if (isEcrProfile(profile)) {
    const d = section(c, root.delivery, 'delivery', ['aws', 'ecr', 'oidcProvider', 'roles', 'ssm', 'environment']) ?? {};
    const awsRaw = section(c, d.aws, 'delivery.aws', ['accountId', 'region']) ?? {};
    const ecrRaw = section(c, d.ecr, 'delivery.ecr', ['repository', 'ownership']) ?? {};
    const rolesRaw = section(c, d.roles, 'delivery.roles', ['pushScanRoleArn', 'pushScanOwnership', 'deployRoleArn', 'deployOwnership']) ?? {};
    const ssmRaw = section(c, d.ssm, 'delivery.ssm', ['instanceId', 'appPort', 'containerName']) ?? {};
    delivery = {
      aws: {
        accountId: str(c, awsRaw.accountId, 'delivery.aws.accountId', { re: RE.accountId, hint: '12 digits, quoted' }),
        region: str(c, awsRaw.region, 'delivery.aws.region', { re: RE.region })
      },
      ecr: {
        repository: str(c, ecrRaw.repository, 'delivery.ecr.repository', { re: RE.ecrRepository }),
        ownership: str(c, ecrRaw.ownership, 'delivery.ecr.ownership', { oneOf: OWNERSHIP, fallback: 'existing' })
      },
      oidcProvider: str(c, d.oidcProvider, 'delivery.oidcProvider', { oneOf: OWNERSHIP, fallback: 'existing' }),
      roles: {
        pushScanRoleArn: str(c, rolesRaw.pushScanRoleArn, 'delivery.roles.pushScanRoleArn', { re: RE.roleArn, required: false }),
        pushScanOwnership: str(c, rolesRaw.pushScanOwnership, 'delivery.roles.pushScanOwnership', { oneOf: OWNERSHIP, fallback: 'existing' }),
        deployRoleArn: str(c, rolesRaw.deployRoleArn, 'delivery.roles.deployRoleArn', { re: RE.roleArn, required: false }),
        deployOwnership: str(c, rolesRaw.deployOwnership, 'delivery.roles.deployOwnership', { oneOf: OWNERSHIP, fallback: 'existing' })
      },
      ssm: {
        instanceId: str(c, ssmRaw.instanceId, 'delivery.ssm.instanceId', { re: RE.instanceId }),
        // Both values reach a root shell on the instance (ssm-deploy.mjs), so
        // they are validated to a strict alphabet here, not merely quoted.
        appPort: str(c, ssmRaw.appPort, 'delivery.ssm.appPort', { re: RE.port, fallback: '3000' }),
        containerName: str(c, ssmRaw.containerName, 'delivery.ssm.containerName', { re: RE.containerName })
      },
      environment: str(c, d.environment, 'delivery.environment', { re: RE.environmentName, required: false, allowEmpty: true }) ?? ''
    };
    for (const [role, ownershipKey] of [['pushScanRoleArn', 'pushScanOwnership'], ['deployRoleArn', 'deployOwnership']]) {
      const arn = delivery.roles[role];
      if (!arn) {
        c.error(
          `delivery.roles.${role}`,
          delivery.roles[ownershipKey] === 'managed'
            ? 'is required to render the delivery workflow. Managed roles are created by `ssd-onboard aws apply` (Phase 2, not yet available); until then create the role and record its ARN, or use the container-self-managed profile'
            : 'is required'
        );
      } else {
        const account = RE.roleArn.exec(arn)?.[1];
        if (account && delivery.aws.accountId && account !== delivery.aws.accountId) {
          c.error(`delivery.roles.${role}`, `is in account ${account}, not delivery.aws.accountId ${delivery.aws.accountId}`);
        }
      }
    }
    if (delivery.roles.pushScanRoleArn && delivery.roles.pushScanRoleArn === delivery.roles.deployRoleArn) {
      c.error(
        'delivery.roles.deployRoleArn',
        'must differ from pushScanRoleArn: no single role may both push an image and deploy it'
      );
    }
  } else if (root.delivery !== undefined && root.delivery !== null) {
    c.error('delivery', 'is only used by the container-ecr-framework-gated profile');
  }

  const notificationsRaw = section(c, root.notifications, 'notifications', ['slack'], { required: false }) ?? {};
  const slackRaw = section(c, notificationsRaw.slack, 'notifications.slack', ['enabled', 'githubSecretName'], { required: false }) ?? {};
  const notifications = {
    slack: {
      enabled: bool(c, slackRaw.enabled, 'notifications.slack.enabled', false),
      githubSecretName: str(c, slackRaw.githubSecretName, 'notifications.slack.githubSecretName', {
        re: RE.secretName,
        fallback: 'SECURITY_NOTIFY_SLACK_URL',
        hint: 'UPPER_SNAKE secret name, not GITHUB_*'
      })
    }
  };

  const bgRaw = section(c, root.breakGlass, 'breakGlass', ['mode'], { required: false }) ?? {};
  const breakGlass = { mode: bgRaw.mode ?? 'disabled' };
  if (breakGlass.mode !== 'disabled') {
    c.error(
      'breakGlass.mode',
      `'${breakGlass.mode}' is not supported by ssd-onboard Phase 1. Break-glass needs observed evidence for conformance, per-repository invoker roles and a broker that derives the repository from a verified identity (Phase 3, not implemented). Use 'disabled': an eligible BLOCK stays blocked`
    );
  }

  // --- cross-field: the rollout state machine ---------------------------------
  if (rollout.gateMode === 'enforce' && baseline.state !== 'accepted') {
    c.error(
      'rollout.gateMode',
      "enforce requires semgrep.baseline.state: accepted. A missing baseline is a fail-closed BLOCK on every run; accept a reviewed baseline first (ssd-onboard baseline accept), then run ssd-onboard promote --enforce"
    );
  }
  if (rollout.gateMode === 'log-only') {
    c.warn('rollout.gateMode', 'log-only: the security gate reports but does not block. It is a rollout mode, not a steady state');
  }

  const config = {
    schemaVersion: SCHEMA_VERSION,
    repository,
    framework,
    profile,
    workflows,
    rollout,
    semgrep,
    gitleaks,
    trufflehog,
    ...(container ? { container } : {}),
    ...(delivery ? { delivery } : {}),
    notifications,
    breakGlass
  };
  return { config, errors: c.errors, warnings: c.warnings };
}

export class ConfigError extends Error {
  constructor(errors) {
    super(`invalid ${CONFIG_PATH}:\n${errors.map((e) => `  - ${e.path}: ${e.message}`).join('\n')}`);
    this.name = 'ConfigError';
    this.errors = errors;
  }
}

export function parseConfig(source, options) {
  const raw = parseYaml(source);
  return validateConfig(raw, options);
}

export async function loadConfig(path, options) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`${path} does not exist. Run \`ssd-onboard init\` first.`, { cause: error });
    }
    throw error;
  }
  return parseConfig(source, options);
}

// --- canonical serialization ----------------------------------------------------

// Drops empty optional values so the file stays readable, in schema order.
function prune(value) {
  if (Array.isArray(value)) {
    return value.map(prune);
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      if (child === undefined || child === null || child === '') {
        continue;
      }
      out[key] = prune(child);
    }
    return out;
  }
  return value;
}

const HEADER = [
  'ssd-onboard configuration — consumer-owned and NON-SECRET.',
  '',
  'Every generated security/delivery workflow is rendered from this file:',
  '  ssd-onboard validate        check it against the repository',
  '  ssd-onboard render          regenerate the workflows and scanner configs',
  '  ssd-onboard render --check  fail if generated files have drifted',
  '',
  'Identifiers only: ARNs, resource names, GitHub secret NAMES. Never put a',
  'credential here (access keys, tokens, webhook URLs, signing secrets); the tool',
  'refuses to read or write one. ssd-onboard rewrites this file canonically, so',
  'record rationale in commit messages and pull requests, not comments here.'
];

const SECTION_COMMENTS = {
  framework: ['Exact framework ref: every generated `uses:` line and toolkit_ref use this value.'],
  profile: ['source-only | container-self-managed | container-ecr-framework-gated'],
  rollout: ['log-only -> enforce only via `ssd-onboard promote --enforce`.'],
  semgrep: [
    'roots: `.` is the whole repository. Narrowing puts everything else outside SAST.',
    'ignore: rendered as .semgrepignore, which REPLACES Semgrep\'s built-in ignore list',
    '(that list silently skips tests/, test/, build/, vendor/, node_modules/).'
  ],
  gitleaks: ['default: no file (full default ruleset). managed: generated with [extend] useDefault = true.'],
  trufflehog: ['Empty = no path exclusions.'],
  notifications: ['Slack webhook: only the GitHub SECRET NAME is recorded; the URL is a credential.'],
  breakGlass: ['Only `disabled` is supported by Phase 1 (see docs/onboarding-cli.md).']
};

export function serializeConfig(config) {
  assertNoSecretValues(config);
  const pruned = prune(config);
  // `schemaVersion` must remain a string even though it looks numeric.
  return stringifyYaml(pruned, { header: HEADER, comments: SECTION_COMMENTS });
}
