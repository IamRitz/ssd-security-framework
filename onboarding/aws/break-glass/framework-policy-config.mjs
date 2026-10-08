// The Phase 3D FRAMEWORK POLICY configuration: which framework commits one
// environment admits (docs/break-glass-repositories.md § Framework policy).
//
//   schemaVersion: "1"
//   kind: break-glass-framework-policy
//   environment: synthetic            # must equal --environment
//   allowedFrameworkShas:             # 0..64, 40 lower-case hex, no duplicates
//     - <sha>
//
// OPERATOR-OWNED, one file per environment, always named explicitly
// (--policy-config). It is never .ssd/onboarding.yml and no consumer
// repository can supply it. `allowedFrameworkShas: []` is valid and admits
// nothing (the revoke-everything value).
//
// The parameter value is rendered by the BROKER's own function
// (broker/identity/framework-policy.mjs renderFrameworkPolicy) and must be
// accepted by the broker's own parser, so what the plan writes is exactly what
// the broker reads. Order in the file is free; the value is always sorted.
// A duplicate is refused rather than silently merged: a list that names a
// commit twice was not reviewed as the set it would become.
import { MAX_ALLOWED_FRAMEWORK_SHAS, parseFrameworkPolicy, renderFrameworkPolicy } from '../../../broker/identity/framework-policy.mjs';
import { findSecretValues } from '../../lib/config.mjs';
import { parseYaml } from '../../lib/yaml.mjs';
import { BREAK_GLASS_ENVIRONMENTS } from '../stack-names.mjs';
import { canonicalJson, sha256 } from '../templates/common.mjs';

export const FRAMEWORK_POLICY_CONFIG_SCHEMA_VERSION = '1';
export const FRAMEWORK_POLICY_CONFIG_KIND = 'break-glass-framework-policy';
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const KEYS = ['schemaVersion', 'kind', 'environment', 'allowedFrameworkShas'];

export class FrameworkPolicyConfigError extends Error {
  constructor(problems) {
    super(`break-glass framework policy configuration is invalid:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'FrameworkPolicyConfigError';
    this.kind = 'configuration';
    this.problems = problems;
  }
}

// raw (parsed YAML) -> frozen { schemaVersion, kind, environment, allowedFrameworkShas (sorted) }.
// `environment` is --environment: the file must name the same one.
export function validateFrameworkPolicyConfig(raw, { environment } = {}) {
  const hits = findSecretValues(raw);
  if (hits.length > 0) {
    throw new FrameworkPolicyConfigError(hits.map((h) => `${h.path}: looks like a ${h.kind} — this file holds commit SHAs only, never a credential`));
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new FrameworkPolicyConfigError(['(root): must be a mapping']);
  }
  const problems = [];
  for (const key of Object.keys(raw)) {
    if (!KEYS.includes(key)) problems.push(`${key}: unknown key (allowed: ${KEYS.join(', ')})`);
  }
  for (const key of KEYS) {
    if (!Object.hasOwn(raw, key)) problems.push(`${key}: required`);
  }
  if (problems.length > 0) throw new FrameworkPolicyConfigError(problems);
  if (raw.schemaVersion !== FRAMEWORK_POLICY_CONFIG_SCHEMA_VERSION) problems.push(`schemaVersion: must be '${FRAMEWORK_POLICY_CONFIG_SCHEMA_VERSION}'`);
  if (raw.kind !== FRAMEWORK_POLICY_CONFIG_KIND) problems.push(`kind: must be '${FRAMEWORK_POLICY_CONFIG_KIND}'`);
  if (!BREAK_GLASS_ENVIRONMENTS.includes(raw.environment)) {
    problems.push(`environment: must be production or synthetic (got '${raw.environment}')`);
  } else if (environment !== undefined && raw.environment !== environment) {
    // A production policy file never plans the synthetic parameter, nor the reverse.
    problems.push(`environment: the file is for '${raw.environment}', not --environment '${environment}'`);
  }
  const shas = raw.allowedFrameworkShas;
  if (!Array.isArray(shas)) {
    problems.push('allowedFrameworkShas: must be a list (an empty list `[]` admits nothing)');
  } else {
    if (shas.length > MAX_ALLOWED_FRAMEWORK_SHAS) problems.push(`allowedFrameworkShas: at most ${MAX_ALLOWED_FRAMEWORK_SHAS} commits (got ${shas.length})`);
    shas.forEach((sha, i) => {
      if (typeof sha !== 'string' || !COMMIT_SHA.test(sha)) problems.push(`allowedFrameworkShas[${i}]: must be a full 40-character lower-case commit SHA (never a tag, branch or abbreviation)`);
    });
    const seen = new Set();
    for (const sha of shas) {
      if (seen.has(sha)) problems.push(`allowedFrameworkShas: ${sha} is listed more than once`);
      seen.add(sha);
    }
  }
  if (problems.length > 0) throw new FrameworkPolicyConfigError(problems);
  const policy = { schemaVersion: FRAMEWORK_POLICY_CONFIG_SCHEMA_VERSION, kind: FRAMEWORK_POLICY_CONFIG_KIND, environment: raw.environment, allowedFrameworkShas: [...shas].sort() };
  // The rendered value must be one the broker accepts: never write a value it
  // would read as malformed (fail closed, but also not what was reviewed).
  const parsed = parseFrameworkPolicy(frameworkPolicyValue(policy), policy.environment);
  if (parsed.state !== 'valid') throw new FrameworkPolicyConfigError([`the rendered value is refused by the broker's parser: ${parsed.reason}`]);
  Object.freeze(policy.allowedFrameworkShas);
  return Object.freeze(policy);
}

export function parseFrameworkPolicyConfig(source, options) {
  let raw;
  try {
    raw = parseYaml(source);
  } catch (error) {
    throw new FrameworkPolicyConfigError([`not valid YAML (the ssd-onboard subset): ${error.message}`]);
  }
  return validateFrameworkPolicyConfig(raw, options);
}

// The canonical, byte-exact SSM parameter value.
export const frameworkPolicyValue = (policy) => renderFrameworkPolicy(policy.environment, policy.allowedFrameworkShas);

export const frameworkPolicyDigestOf = (policy) => sha256(canonicalJson(policy));
