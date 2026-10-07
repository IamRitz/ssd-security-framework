// Which framework commits may file break-glass requests in this environment
// (Phase 3D, docs/break-glass-repositories.md).
//
// The verified GitHub OIDC token proves WHICH commit of the framework's
// _break-glass-lambda.yml built a request (job_workflow_sha). That commit is
// what re-derived eligibility, run binding and the gate digest, so it is the
// thing to authorize. Each environment keeps its own explicit allowed set in
// one SSM parameter, written only through the governance stack:
//
//   /ssd/break-glass/<environment>/governance/allowed-framework-shas
//   Type String, value (canonical, byte-exact):
//   {"schemaVersion":1,"environment":"<environment>","shas":["<sha>",…]}
//
// The broker checks it on notify, on every status call, and again when an
// approver clicks (against the stored request's commit), so removing a commit
// also revokes its pending requests.
//
// Fail closed, with the reason kept distinct for operators:
//   allowed        the commit is in the set              -> proceed
//   not_allowed    a valid set without it ("shas": [])  -> refused
//   absent         no such parameter                     -> refused
//   malformed      anything but the canonical form       -> refused (never partially used)
//   unverified     SSM refused, failed or timed out      -> refused (NOT "absent")
//   misconfigured  bad environment or commit             -> refused, no SSM call
//
// No cache: a removed commit is refused on the next call.
import { BREAK_GLASS_ENVIRONMENTS } from '../authorize/approvers.mjs';

export const FRAMEWORK_POLICY_SCHEMA_VERSION = 1;
export const MAX_ALLOWED_FRAMEWORK_SHAS = 64;
const MAX_VALUE_LENGTH = 4096;
const COMMIT_SHA = /^[0-9a-f]{40}$/;
const KEYS = ['schemaVersion', 'environment', 'shas'];

export const FRAMEWORK_POLICY_STATES = Object.freeze(['allowed', 'not_allowed', 'absent', 'malformed', 'unverified', 'misconfigured']);

// -> the exact parameter name, or null for an unknown environment.
export function frameworkPolicyParameterName(environment) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) return null;
  return `/ssd/break-glass/${environment}/governance/allowed-framework-shas`;
}

// The one canonical value for a set: keys in this order, SHAs ascending.
export function renderFrameworkPolicy(environment, shas) {
  return JSON.stringify({ schemaVersion: FRAMEWORK_POLICY_SCHEMA_VERSION, environment, shas: [...shas].sort() });
}

const result = (state, reason, shas = null) => ({ state, reason, shas });

// A parameter value -> { state: 'valid', shas: Set } or { state: 'malformed' }.
// Anything that is not exactly the canonical form is malformed: a value that
// does not parse as written is not the set its owner reviewed.
export function parseFrameworkPolicy(value, environment) {
  if (typeof value !== 'string' || value.length > MAX_VALUE_LENGTH) return result('malformed', 'value is not a bounded string');
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return result('malformed', 'value is not JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return result('malformed', 'value is not a JSON object');
  const keys = Object.keys(parsed);
  if (keys.length !== KEYS.length || keys.some((key, i) => key !== KEYS[i])) {
    return result('malformed', `keys must be exactly ${KEYS.join(', ')}, in that order`);
  }
  if (parsed.schemaVersion !== FRAMEWORK_POLICY_SCHEMA_VERSION) return result('malformed', 'unsupported schemaVersion');
  // A value copied from the other environment admits nothing here.
  if (parsed.environment !== environment) return result('malformed', `the value is for '${parsed.environment}', not '${environment}'`);
  const { shas } = parsed;
  if (!Array.isArray(shas)) return result('malformed', 'shas is not an array');
  if (shas.length > MAX_ALLOWED_FRAMEWORK_SHAS) return result('malformed', `more than ${MAX_ALLOWED_FRAMEWORK_SHAS} commits`);
  if (!shas.every((sha) => typeof sha === 'string' && COMMIT_SHA.test(sha))) {
    return result('malformed', 'an entry is not a 40-character lower-case commit SHA');
  }
  // Strictly ascending: canonical order, and no duplicates.
  for (let i = 1; i < shas.length; i += 1) {
    if (!(shas[i - 1] < shas[i])) return result('malformed', 'commits are not strictly ascending (unsorted or duplicated)');
  }
  return result('valid', null, new Set(shas));
}

// getParameter(name) -> { Type, Value } (the SSM GetParameter `Parameter`), or
// throws; an error named ParameterNotFound means the parameter does not exist.
export function createFrameworkPolicy({ getParameter, environment }) {
  return {
    async check(sha) {
      const name = frameworkPolicyParameterName(environment);
      if (!name) return result('misconfigured', 'invalid break-glass environment');
      if (typeof sha !== 'string' || !COMMIT_SHA.test(sha)) return result('misconfigured', 'no valid framework commit to check');
      let parameter;
      try {
        parameter = await getParameter(name);
      } catch (error) {
        if (error?.name === 'ParameterNotFound') return result('absent', 'no framework policy parameter');
        // Access denied, throttling, timeout, network: the set is UNKNOWN.
        return result('unverified', `framework policy lookup failed (${error?.name || 'error'})`);
      }
      if (!parameter || parameter.Type !== 'String') return result('malformed', 'parameter is not of type String');
      const parsed = parseFrameworkPolicy(parameter.Value, environment);
      if (parsed.state !== 'valid') return parsed;
      return parsed.shas.has(sha) ? result('allowed', null) : result('not_allowed', 'the framework commit is not in the allowed set');
    }
  };
}

// Any lookup result -> a decision that can only be `allowed` when the result
// says exactly that. A missing policy, a thrown check, or an unknown state
// never becomes allowed.
export async function decideFramework(frameworkPolicy, sha) {
  if (!frameworkPolicy || typeof frameworkPolicy.check !== 'function') return result('misconfigured', 'no framework policy configured');
  let decision;
  try {
    decision = await frameworkPolicy.check(sha);
  } catch (error) {
    return result('unverified', `framework policy check failed (${error?.name || 'error'})`);
  }
  if (decision?.state === 'allowed') return result('allowed', null);
  const state = FRAMEWORK_POLICY_STATES.includes(decision?.state) ? decision.state : 'misconfigured';
  return result(state, decision?.reason ?? 'unrecognized framework policy result');
}
