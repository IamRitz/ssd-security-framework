// The Phase 3D REPOSITORY configuration: one repository's break-glass
// onboarding (docs/break-glass-repositories.md § Repository configuration).
//
//   schemaVersion: "1"
//   kind: break-glass-repository
//   repository:
//     slug: owner/repo            # must equal GitHub's full_name, ignoring case
//     id: "123456789"             # the immutable repository_id (quoted)
//   environments:                 # at least one; an absent one is not onboarded there
//     synthetic:
//       approvers:
//         - U0123456789
//     production:
//       approvers: []             # valid: nobody is authorized
//
// OPERATOR-OWNED and always named explicitly (--repository-config). It is
// never .ssd/onboarding.yml: a consumer repository can choose neither its
// approvers nor its AWS authority. The approver list is validated by the
// BROKER's own parser (broker/authorize/approvers.mjs), so what is planned is
// what the broker reads.
//
// The `oidc` override (a customized subject) is NOT accepted by this version:
// a customized subject may be used only once the subject GitHub emits is
// proven from a recorded run, which is not implemented. A repository whose
// subject is customized therefore cannot be planned (fail closed); a subject
// is never constructed from owner and repository ids.
import { parseApproverList } from '../../../broker/authorize/approvers.mjs';
import { findSecretValues } from '../../lib/config.mjs';
import { parseYaml } from '../../lib/yaml.mjs';
import { BREAK_GLASS_ENVIRONMENTS, REPOSITORY_ID } from '../stack-names.mjs';
import { canonicalJson, sha256 } from '../templates/common.mjs';

export const REPOSITORY_CONFIG_SCHEMA_VERSION = '1';
export const REPOSITORY_CONFIG_KIND = 'break-glass-repository';
// GitHub owner/name, as the github side validates them (onboarding/github/gh-cli.mjs SLUG).
const SLUG = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/;

export class RepositoryConfigError extends Error {
  constructor(problems) {
    super(`break-glass repository configuration is invalid:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'RepositoryConfigError';
    this.kind = 'configuration';
    this.problems = problems;
  }
}

const isMap = (v) => v && typeof v === 'object' && !Array.isArray(v);
function exactKeys(problems, value, path, allowed, required = allowed) {
  if (!isMap(value)) {
    problems.push(`${path || '(root)'}: must be a mapping`);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      problems.push(key === 'oidc' && !path
        ? 'oidc: a customized OIDC subject is not supported by this version (proving the subject GitHub emits from a recorded run is not implemented); only the default subject repo:<owner>/<repo>:pull_request is planned'
        : `${path ? `${path}.` : ''}${key}: unknown key (allowed: ${allowed.join(', ')})`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) problems.push(`${path ? `${path}.` : ''}${key}: required`);
  }
  return true;
}

// raw (parsed YAML) -> frozen config.
export function validateRepositoryConfig(raw) {
  const hits = findSecretValues(raw);
  if (hits.length > 0) {
    throw new RepositoryConfigError(hits.map((h) => `${h.path}: looks like a ${h.kind} — this file holds identifiers only, never a credential`));
  }
  const problems = [];
  if (!exactKeys(problems, raw, '', ['schemaVersion', 'kind', 'repository', 'environments'])) throw new RepositoryConfigError(problems);
  if (raw.schemaVersion !== REPOSITORY_CONFIG_SCHEMA_VERSION) problems.push(`schemaVersion: must be '${REPOSITORY_CONFIG_SCHEMA_VERSION}'`);
  if (raw.kind !== REPOSITORY_CONFIG_KIND) problems.push(`kind: must be '${REPOSITORY_CONFIG_KIND}'`);
  const repository = {};
  if (exactKeys(problems, raw.repository, 'repository', ['slug', 'id'])) {
    if (typeof raw.repository.slug !== 'string' || !SLUG.test(raw.repository.slug)) problems.push(`repository.slug: '${raw.repository.slug}' is not a GitHub owner/name`);
    else repository.slug = raw.repository.slug;
    if (typeof raw.repository.id !== 'string' || !REPOSITORY_ID.test(raw.repository.id)) {
      problems.push(`repository.id: must be the numeric repository_id as a quoted string (got ${JSON.stringify(raw.repository.id)})`);
    } else {
      repository.id = raw.repository.id;
    }
  }
  const environments = {};
  if (exactKeys(problems, raw.environments, 'environments', [...BREAK_GLASS_ENVIRONMENTS], [])) {
    if (Object.keys(raw.environments).length === 0) problems.push('environments: at least one of production, synthetic');
    for (const env of BREAK_GLASS_ENVIRONMENTS.filter((e) => Object.hasOwn(raw.environments, e))) {
      const path = `environments.${env}`;
      if (!exactKeys(problems, raw.environments[env], path, ['approvers'])) continue;
      const approvers = raw.environments[env].approvers;
      if (!Array.isArray(approvers)) {
        problems.push(`${path}.approvers: must be a list (an empty list \`[]\` authorizes nobody)`);
        continue;
      }
      const parsed = parseApproverList(JSON.stringify(approvers));
      if (parsed.state === 'malformed') {
        problems.push(`${path}.approvers: refused by the broker's parser: ${parsed.reason}`);
        continue;
      }
      environments[env] = Object.freeze({ approvers: Object.freeze([...approvers]) });
    }
  }
  if (problems.length > 0) throw new RepositoryConfigError(problems);
  return Object.freeze({ schemaVersion: REPOSITORY_CONFIG_SCHEMA_VERSION, kind: REPOSITORY_CONFIG_KIND, repository: Object.freeze(repository), environments: Object.freeze(environments) });
}

export function parseRepositoryConfig(source) {
  let raw;
  try {
    raw = parseYaml(source);
  } catch (error) {
    throw new RepositoryConfigError([`not valid YAML (the ssd-onboard subset): ${error.message}`]);
  }
  return validateRepositoryConfig(raw);
}

// The canonical, byte-exact approver parameter value.
export const approverValue = (config, environment) => JSON.stringify(config.environments[environment].approvers);

export const repositoryDigestOf = (config) => sha256(canonicalJson(config));
