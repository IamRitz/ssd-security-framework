// The Phase 3 break-glass OPERATOR configuration: the identifiers the two
// shared break-glass stacks need, and nothing else.
//
// It is NOT .ssd/onboarding.yml. That file is consumer-owned and per
// repository; the break-glass stacks are account-level infrastructure owned by
// whoever operates the broker. Phase 1 (validate/render/init) never reads or
// writes this file, and this module never reads .ssd/onboarding.yml. Its path
// is always given explicitly (--operator-config); there is no default. The one
// file read is lib/operator-file.mjs (nothing under onboarding/aws/ touches
// the filesystem except the plan record).
//
//   schemaVersion: 1
//   framework:
//     repository: IamRitz/ssd-security-framework
//     ref: <40-hex commit>        # the checkout `aws plan` must run from (as framework.ref)
//   aws:
//     accountId: "123456789012"
//     region: us-east-1
//   environments:
//     production:
//       slackChannelId: C0123456789
//       artifact:                 # an ALREADY-PUBLISHED, immutable Lambda bundle
//         bucket: …               # private, versioned (checked by plan and verify)
//         key: …
//         versionId: …            # an S3 object version, never "null"
//         sha256: <64 hex>        # sha256 of the .zip bytes (sha256sum output)
//     synthetic:
//       slackChannelId: C0987654321
//       artifact: { … }           # may be the same artifact as production
//
// IDENTIFIERS ONLY. A credential-shaped value anywhere refuses the file. Both
// environments are required, so the production/synthetic separation (Slack
// channel, and every derived resource name) is checked as a pair, every time.
// Reserved concurrency is not configurable yet (aws verify WARNs that no cap
// is set); an unknown key is refused rather than ignored, so a future
// `reservedConcurrency` is an explicit schema change.
import { findSecretValues } from '../../lib/config.mjs';
import { parseYaml } from '../../lib/yaml.mjs';
import { BREAK_GLASS_ENVIRONMENTS } from '../stack-names.mjs';
import { canonicalJson, sha256 } from '../templates/common.mjs';
import { assertSeparated } from './names.mjs';

export const OPERATOR_SCHEMA_VERSION = '1';

export class OperatorConfigError extends Error {
  constructor(problems) {
    super(`break-glass operator configuration is invalid:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'OperatorConfigError';
    this.kind = 'configuration';
    this.problems = problems;
  }
}

const RE = {
  repository: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  sha: /^[0-9a-f]{40}$/,
  accountId: /^\d{12}$/,
  region: /^[a-z]{2}(?:-[a-z]+)+-\d$/,
  // Slack conversation ids: public (C…) or private (G…) channels.
  slackChannelId: /^[CG][A-Z0-9]{8,20}$/,
  // S3 bucket naming rules (no dots: a dotted name breaks virtual-host TLS).
  bucket: /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/,
  // A conservative object key: no leading '/', no '//' and no '..' segment.
  key: /^(?!.*\/\/)(?!(?:.*\/)?\.\.(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/,
  versionId: /^[A-Za-z0-9._-]{1,1024}$/,
  sha256: /^[0-9a-f]{64}$/
};

function keys(problems, value, path, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    problems.push(`${path || '(root)'}: must be a mapping`);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      problems.push(`${path ? `${path}.` : ''}${key}: unknown key (allowed: ${allowed.join(', ')})`);
    }
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key)) {
      problems.push(`${path ? `${path}.` : ''}${key}: required`);
    }
  }
  return true;
}

function str(problems, value, path, re, hint) {
  if (typeof value !== 'string' || !re.test(value)) {
    problems.push(`${path}: ${typeof value === 'string' ? `'${value}' is not ${hint}` : `must be a string (${hint})`}`);
    return null;
  }
  return value;
}

// raw (parsed YAML) -> frozen operator config. Throws OperatorConfigError.
export function validateOperatorConfig(raw) {
  const problems = [];
  const hits = findSecretValues(raw);
  if (hits.length > 0) {
    throw new OperatorConfigError(hits.map((h) => `${h.path}: looks like a ${h.kind} — this file holds identifiers only, never a credential or secret value`));
  }
  if (!keys(problems, raw, '', ['schemaVersion', 'framework', 'aws', 'environments'])) {
    throw new OperatorConfigError(problems);
  }
  if (raw.schemaVersion !== OPERATOR_SCHEMA_VERSION) {
    problems.push(`schemaVersion: must be '${OPERATOR_SCHEMA_VERSION}'`);
  }
  const framework = {};
  if (keys(problems, raw.framework, 'framework', ['repository', 'ref'])) {
    framework.repository = str(problems, raw.framework.repository, 'framework.repository', RE.repository, 'an owner/repository slug');
    framework.ref = str(problems, raw.framework.ref, 'framework.ref', RE.sha, 'a full 40-character commit SHA (never a tag or branch)');
  }
  const aws = {};
  if (keys(problems, raw.aws, 'aws', ['accountId', 'region'])) {
    aws.accountId = str(problems, raw.aws.accountId, 'aws.accountId', RE.accountId, '12 digits, quoted');
    aws.region = str(problems, raw.aws.region, 'aws.region', RE.region, 'an AWS region name');
  }
  const environments = {};
  if (keys(problems, raw.environments, 'environments', [...BREAK_GLASS_ENVIRONMENTS])) {
    for (const env of BREAK_GLASS_ENVIRONMENTS) {
      const e = raw.environments[env];
      const path = `environments.${env}`;
      if (!keys(problems, e, path, ['slackChannelId', 'artifact'])) {
        continue;
      }
      const out = { slackChannelId: str(problems, e.slackChannelId, `${path}.slackChannelId`, RE.slackChannelId, 'a Slack channel id (C… or G…)'), artifact: null };
      if (keys(problems, e.artifact, `${path}.artifact`, ['bucket', 'key', 'versionId', 'sha256'])) {
        const a = e.artifact;
        out.artifact = {
          bucket: str(problems, a.bucket, `${path}.artifact.bucket`, RE.bucket, 'an S3 bucket name (lower-case, no dots)'),
          key: str(problems, a.key, `${path}.artifact.key`, RE.key, "an S3 object key (no leading '/', '//' or '..')"),
          versionId: str(problems, a.versionId, `${path}.artifact.versionId`, RE.versionId, 'an S3 object version id'),
          sha256: str(problems, a.sha256, `${path}.artifact.sha256`, RE.sha256, '64 lower-case hex characters (sha256sum of the .zip)')
        };
        if (a.versionId === 'null') {
          problems.push(`${path}.artifact.versionId: 'null' is the version id of an object written while versioning was off; the artifact must be an immutable object version`);
        }
      }
      environments[env] = out;
    }
  }
  if (problems.length === 0) {
    const p = environments.production.slackChannelId;
    const s = environments.synthetic.slackChannelId;
    try {
      assertSeparated({ account: aws.accountId, region: aws.region }, { production: p, synthetic: s });
    } catch (error) {
      problems.push(`environments: ${error.message}`);
    }
  }
  if (problems.length > 0) {
    throw new OperatorConfigError(problems);
  }
  return deepFreeze({ schemaVersion: OPERATOR_SCHEMA_VERSION, framework, aws, environments });
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

export function parseOperatorConfig(source) {
  let raw;
  try {
    raw = parseYaml(source);
  } catch (error) {
    throw new OperatorConfigError([`not valid YAML (the ssd-onboard subset): ${error.message}`]);
  }
  return validateOperatorConfig(raw);
}

// What a break-glass plan binds as "the configuration it was made from".
export const operatorDigestOf = (operator) => sha256(canonicalJson(operator));
