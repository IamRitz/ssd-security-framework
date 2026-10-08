// An IAM role: trust policy, identity policies, tags — and, where the caller
// may, simulate-principal-policy results for the actions the role needs.
import { tagList } from './oidc-provider.mjs';
import { present, read, unverified } from './result.mjs';

export const roleName = (arn) => arn.split('/').pop();

// -> result whose value is { arn, name, trust, tags[], permissionsBoundary }
export async function discoverRole(aws, arn) {
  const got = await read(aws, ['iam', 'get-role', '--role-name', roleName(arn)], { notFound: ['NoSuchEntity'] });
  if (got.state !== 'present') {
    return got;
  }
  const role = got.value.Role ?? {};
  return present({
    arn: typeof role.Arn === 'string' ? role.Arn : null,
    name: role.RoleName ?? null,
    roleId: typeof role.RoleId === 'string' ? role.RoleId : null,
    trust: role.AssumeRolePolicyDocument ?? null,
    tags: tagList(role.Tags),
    permissionsBoundary: role.PermissionsBoundary?.PermissionsBoundaryArn ?? null,
    maxSessionDuration: Number.isInteger(role.MaxSessionDuration) ? role.MaxSessionDuration : null,
    path: typeof role.Path === 'string' ? role.Path : null
  });
}

// -> { policies: [{ name, kind, document }], complete, errors[] }
export async function discoverRolePolicies(aws, name) {
  const policies = [];
  const errors = [];
  const inline = await read(aws, ['iam', 'list-role-policies', '--role-name', name]);
  if (inline.state === 'present') {
    for (const policyName of Array.isArray(inline.value.PolicyNames) ? inline.value.PolicyNames : []) {
      const got = await read(aws, ['iam', 'get-role-policy', '--role-name', name, '--policy-name', String(policyName)], { notFound: ['NoSuchEntity'] });
      if (got.state === 'present') {
        policies.push({ name: `inline:${policyName}`, kind: 'inline', document: got.value.PolicyDocument });
      } else {
        errors.push(got.state === 'unverified' ? got.error : { kind: 'not-found', message: `inline policy ${policyName} disappeared` });
      }
    }
  } else {
    errors.push(inline.error ?? { kind: 'not-found', message: 'role disappeared' });
  }
  const attached = await read(aws, ['iam', 'list-attached-role-policies', '--role-name', name]);
  if (attached.state === 'present') {
    for (const entry of Array.isArray(attached.value.AttachedPolicies) ? attached.value.AttachedPolicies : []) {
      const policyArn = String(entry?.PolicyArn ?? '');
      const meta = await read(aws, ['iam', 'get-policy', '--policy-arn', policyArn], { notFound: ['NoSuchEntity'] });
      if (meta.state !== 'present') {
        errors.push(meta.state === 'unverified' ? meta.error : { kind: 'not-found', message: `attached policy ${policyArn} not found` });
        continue;
      }
      const versionId = String(meta.value.Policy?.DefaultVersionId ?? '');
      const version = await read(aws, ['iam', 'get-policy-version', '--policy-arn', policyArn, '--version-id', versionId], { notFound: ['NoSuchEntity'] });
      if (version.state === 'present') {
        policies.push({ name: `attached:${entry.PolicyName ?? policyArn}`, kind: 'attached', arn: policyArn, document: version.value.PolicyVersion?.Document });
      } else {
        errors.push(version.state === 'unverified' ? version.error : { kind: 'not-found', message: `policy version ${versionId} of ${policyArn} not found` });
      }
    }
  } else {
    errors.push(attached.error ?? { kind: 'not-found', message: 'role disappeared' });
  }
  return { policies, complete: errors.length === 0, errors };
}

// -> result whose value is [{ action, resource, decision }]
export async function simulateRole(aws, arn, groups) {
  const out = [];
  for (const group of groups) {
    const got = await read(aws, ['iam', 'simulate-principal-policy', '--policy-source-arn', arn, '--action-names', JSON.stringify(group.actions), '--resource-arns', JSON.stringify([group.resource])]);
    if (got.state !== 'present') {
      return got.state === 'unverified' ? got : unverified({ kind: 'aws-error', message: 'simulation returned not-found' });
    }
    for (const r of Array.isArray(got.value.EvaluationResults) ? got.value.EvaluationResults : []) {
      out.push({ action: String(r?.EvalActionName ?? ''), resource: String(r?.EvalResourceName ?? group.resource), decision: String(r?.EvalDecision ?? 'unknown') });
    }
  }
  return present(out);
}

// The decisions simulate-principal-policy reports. Anything else is malformed.
export const SIMULATION_DECISIONS = Object.freeze(['allowed', 'explicitDeny', 'implicitDeny']);

// STRICT simulation for `aws verify` (Phase 2D). probes: [{ action, resource }].
// One call per resource. Every probe must come back exactly once — matched by
// action (case-insensitive, as IAM) AND resource — with a recognised decision;
// a missing, duplicated or unrecognised answer, or a truncated page, makes the
// whole result unverified. Never a partial answer.
// -> result whose value is [{ action, resource, decision, missingContext[] }]
export async function simulateProbes(aws, arn, probes) {
  const byResource = new Map();
  for (const p of probes) {
    if (!byResource.has(p.resource)) {
      byResource.set(p.resource, []);
    }
    if (!byResource.get(p.resource).includes(p.action)) {
      byResource.get(p.resource).push(p.action);
    }
  }
  const malformed = (message) => unverified({ kind: 'malformed-response', operation: 'iam simulate-principal-policy', message });
  const out = [];
  for (const [resource, actions] of byResource) {
    const got = await read(aws, ['iam', 'simulate-principal-policy', '--policy-source-arn', arn, '--action-names', JSON.stringify(actions), '--resource-arns', JSON.stringify([resource])]);
    if (got.state !== 'present') {
      return got.state === 'unverified' ? got : unverified({ kind: 'aws-error', operation: 'iam simulate-principal-policy', message: 'simulation returned not-found' });
    }
    if (got.value.IsTruncated === true) {
      return malformed('the simulation result is truncated');
    }
    if (!Array.isArray(got.value.EvaluationResults)) {
      return malformed('EvaluationResults is not a list');
    }
    for (const action of actions) {
      const answers = got.value.EvaluationResults.filter((r) => typeof r?.EvalActionName === 'string' && r.EvalActionName.toLowerCase() === action.toLowerCase());
      if (answers.length !== 1) {
        return malformed(`${answers.length === 0 ? 'no' : 'more than one'} evaluation result for ${action}`);
      }
      const r = answers[0];
      if (r.EvalResourceName !== resource) {
        return malformed(`the evaluation result for ${action} names resource ${String(r.EvalResourceName)}, not ${resource}`);
      }
      if (!SIMULATION_DECISIONS.includes(r.EvalDecision)) {
        return malformed(`the decision for ${action} on ${resource} is ${r.EvalDecision === undefined ? 'missing' : `'${String(r.EvalDecision)}'`}`);
      }
      const missingContext = Array.isArray(r.MissingContextValues) ? r.MissingContextValues.map(String) : [];
      out.push({ action, resource, decision: r.EvalDecision, missingContext });
    }
  }
  return present(out);
}
