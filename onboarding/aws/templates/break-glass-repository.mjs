// The Phase 3D repository stack of one repository in one environment:
// ssd-break-glass-<environment>-repo-<repository_id>, holding EXACTLY:
//
//   InvokerRole         AWS::IAM::Role ssd-break-glass-<env>-invoker-<repository_id>
//                       (policy/break-glass-invoker.mjs: trust and its one
//                       inline policy, MaxSessionDuration 3600)
//   ApproverParameter   AWS::SSM::Parameter /ssd/break-glass/<env>/approvers/<repository_id>
//                       String, Standard, text; JSON of the configured approvers
//                       (`[]` is valid: nobody is authorized)
//
// Both retained: deleting the stack never revokes. Offboarding is `approvers:
// []`, apply, and only then anything else.
import { invokerArns, invokerNames } from '../break-glass/names.mjs';
import { approverValue } from '../break-glass/repository-config.mjs';
import { INVOKER_POLICY_NAME, MAX_SESSION_SECONDS, defaultSubject, invokerPermissionPolicy, invokerTrustPolicy } from '../policy/break-glass-invoker.mjs';
import { retained, ssdTags, template } from './common.mjs';

export const REPOSITORY_LOGICAL_IDS = Object.freeze({ role: 'InvokerRole', approvers: 'ApproverParameter' });
export const REPOSITORY_RESOURCE_TYPES = Object.freeze({ [REPOSITORY_LOGICAL_IDS.role]: 'AWS::IAM::Role', [REPOSITORY_LOGICAL_IDS.approvers]: 'AWS::SSM::Parameter' });

// -> the exact approver parameter (verify compares the live one to it).
export function approverParameter(config, environment) {
  return Object.freeze({ name: invokerNames(environment, config.repository.id).approverParameter, type: 'String', tier: 'Standard', dataType: 'text', value: approverValue(config, environment) });
}

// fullName: GitHub's full_name, as `aws plan` read it (the subject's spelling).
export function renderRepositoryTemplate({ config, environment, fullName, partition, account, region }) {
  if (!Object.hasOwn(config.environments, environment)) {
    throw new Error(`the repository is not configured for '${environment}'`);
  }
  if (fullName.toLowerCase() !== config.repository.slug.toLowerCase()) {
    throw new Error(`GitHub's full_name ${fullName} is not the configured ${config.repository.slug}`);
  }
  const target = { partition, account, region };
  const n = invokerNames(environment, config.repository.id);
  const trust = invokerTrustPolicy({ partition, account, subject: defaultSubject(fullName) });
  const permissions = invokerPermissionPolicy(environment, target);
  const tags = ssdTags({ scope: 'break-glass', environment });
  const p = approverParameter(config, environment);
  return {
    template: template(`ssd-onboard ${environment} break-glass repository ${config.repository.id}: invoker role and approvers (Phase 3D)`, {
      [REPOSITORY_LOGICAL_IDS.role]: retained('AWS::IAM::Role', {
        RoleName: n.role,
        Description: `Invokes the ${environment} break-glass CI broker for pull_request runs of GitHub repository ${config.repository.id}`,
        AssumeRolePolicyDocument: trust,
        MaxSessionDuration: MAX_SESSION_SECONDS,
        Policies: [{ PolicyName: INVOKER_POLICY_NAME, PolicyDocument: permissions }],
        Tags: tags
      }),
      [REPOSITORY_LOGICAL_IDS.approvers]: retained('AWS::SSM::Parameter', {
        Name: p.name,
        Type: p.type,
        Tier: p.tier,
        DataType: p.dataType,
        Value: p.value,
        Description: `Slack user ids who may approve ${environment} break-glass requests of GitHub repository ${config.repository.id}. [] authorizes nobody.`,
        Tags: Object.fromEntries(tags.map((t) => [t.Key, t.Value]))
      })
    }),
    policies: { [REPOSITORY_LOGICAL_IDS.role]: { role: 'invoker', arn: invokerArns(environment, config.repository.id, target).role, trust, permissions } },
    parameter: p
  };
}
