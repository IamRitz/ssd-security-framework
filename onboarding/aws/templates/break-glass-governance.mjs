// The Phase 3D governance stack of one environment:
// ssd-break-glass-<environment>-governance, holding EXACTLY ONE resource —
// the environment's allowed-framework-commit parameter
// (docs/break-glass-repositories.md § The allowed-commit parameter):
//
//   AllowedFrameworkShas   AWS::SSM::Parameter
//                          /ssd/break-glass/<environment>/governance/allowed-framework-shas
//                          String, Standard, text; the canonical value the
//                          broker parses (framework-policy-config.mjs)
//
// Retained, like every managed resource: deleting the stack or removing the
// resource never revokes anything. To revoke, plan `allowedFrameworkShas: []`
// and apply. Nothing else lives here: no role, no policy, no other parameter.
import { frameworkPolicyParameterName } from '../../../broker/identity/framework-policy.mjs';
import { assertEnvironment } from '../break-glass/names.mjs';
import { frameworkPolicyValue } from '../break-glass/framework-policy-config.mjs';
import { retained, ssdTags, template } from './common.mjs';

export const GOVERNANCE_LOGICAL_ID = 'AllowedFrameworkShas';
export const GOVERNANCE_RESOURCE_TYPES = Object.freeze({ [GOVERNANCE_LOGICAL_ID]: 'AWS::SSM::Parameter' });

// -> the exact properties of the parameter (verify compares the live one to these).
export function governanceParameter(policy) {
  const environment = assertEnvironment(policy.environment);
  return Object.freeze({ name: frameworkPolicyParameterName(environment), type: 'String', tier: 'Standard', dataType: 'text', value: frameworkPolicyValue(policy) });
}

export function renderGovernanceTemplate({ policy, environment }) {
  if (policy.environment !== assertEnvironment(environment)) {
    throw new Error(`the framework policy is for '${policy.environment}', not '${environment}'`);
  }
  const p = governanceParameter(policy);
  // SSM parameter tags are a map, not CloudFormation's [{ Key, Value }].
  const tags = Object.fromEntries(ssdTags({ scope: 'break-glass', environment }).map((t) => [t.Key, t.Value]));
  return {
    template: template(`ssd-onboard ${environment} break-glass governance: the allowed framework commits (Phase 3D)`, {
      [GOVERNANCE_LOGICAL_ID]: retained('AWS::SSM::Parameter', {
        Name: p.name,
        Type: p.type,
        Tier: p.tier,
        DataType: p.dataType,
        Value: p.value,
        Description: `Framework commits admitted to file ${environment} break-glass requests. Owned by ssd-onboard; change it only through aws plan/apply.`,
        Tags: tags
      })
    }),
    parameter: p
  };
}
