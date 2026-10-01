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
    trust: role.AssumeRolePolicyDocument ?? null,
    tags: tagList(role.Tags),
    permissionsBoundary: role.PermissionsBoundary?.PermissionsBoundaryArn ?? null
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
