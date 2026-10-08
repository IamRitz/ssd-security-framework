// `ssd-onboard aws plan --scope break-glass-governance --environment <env>`
// (Phase 3D): one UNEXECUTED change set for ssd-break-glass-<env>-governance,
// whose only resource is /ssd/break-glass/<env>/governance/allowed-framework-shas.
//
// Same contract as every other plan (plan.mjs recordPlans): nothing here can
// execute a change set; governancePlanningAws() allows only the governance
// reads and the change-set calls on the two governance stacks.
//
// Order is part of the contract; each step blocks before the next:
//   1. the framework checkout is bound to the operator config's framework.ref;
//   2. ADMISSION, locally, before AWS (break-glass/admission.mjs): every
//      listed commit exists in the checkout, its _break-glass-lambda.yml binds
//      itself, and — production only — it is merged to origin/main (the
//      commit checked against is recorded in plan.json);
//   3. region; 4. sts get-caller-identity: the configured account, never root;
//   5. the stack: absent, an ssd-onboard placeholder, or a settled stack tagged
//      for THIS environment;
//   6. the parameter: absent, or exactly this stack's own resource. A
//      parameter that merely has the name is never adopted;
//   7. render; recordPlans().
import { governancePlanningAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { PlanError, evaluateResource, recordPlans, report, stackState } from '../plan.mjs';
import { BREAK_GLASS_ENVIRONMENTS, BREAK_GLASS_GOVERNANCE_STACKS, breakGlassGovernanceStackKind } from '../stack-names.mjs';
import { canonicalJson, sha256, ssdTags } from '../templates/common.mjs';
import { GOVERNANCE_LOGICAL_ID, renderGovernanceTemplate } from '../templates/break-glass-governance.mjs';
import { frameworkProblems } from '../../lib/framework.mjs';
import { admissionFindings, frameworkGit } from './admission.mjs';
import { discoverParameter } from './discover.mjs';
import { frameworkPolicyDigestOf } from './framework-policy-config.mjs';
import { breakGlassNames } from './names.mjs';
import { operatorDigestOf } from './operator-config.mjs';

const FAIL = 'FAIL';
const finding = (severity, kind, message) => ({ severity, kind, message });

// What a governance plan binds as "the configuration it was made from": the
// operator config AND the policy file, so apply refuses if either changed.
export const governanceDigestOf = (operator, policy) => sha256(canonicalJson({ operator: operatorDigestOf(operator), frameworkPolicy: frameworkPolicyDigestOf(policy) }));

export async function awsPlanBreakGlassGovernance({ operator, policy, environment, region: explicitRegion = null, exec, env = process.env, framework, git = null, root, deadlineMs, now, sleep }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
    throw new PlanError('unsupported-environment', `--environment must be production or synthetic (got '${environment}')`);
  }
  if (policy?.environment !== environment) {
    throw new PlanError('environment-mismatch', `the framework policy is for '${policy?.environment}', not --environment '${environment}'`);
  }
  const scope = 'break-glass';
  const account = operator.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const calls = [];
  const base = {
    scope,
    target: { repository: null, environment, account, region: resolved.region, regionSource: resolved.source, caller: null },
    framework: { repository: operator.framework.repository, ref: operator.framework.ref },
    calls
  };

  const bindingProblems = frameworkProblems(framework, operator);
  if (bindingProblems.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: bindingProblems.map((m) => finding(FAIL, 'framework-binding', m)), skipped: 'the framework checkout is not bound to framework.ref: AWS was not contacted' });
  }
  const admission = await admissionFindings({ environment, shas: policy.allowedFrameworkShas, git: git ?? frameworkGit(framework.root) });
  // Anything short of a proven admission blocks (NOT VERIFIED included).
  if (admission.findings.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: admission.findings.map((f) => finding(FAIL, f.kind, f.message)), skipped: 'a listed framework commit is not admissible: AWS was not contacted' });
  }
  const regionC = regionCheck(resolved);
  if (regionC.status === FAIL) {
    return report(base, { outcome: 'BLOCKED', findings: regionC.findings.map((f) => finding(FAIL, f.kind, f.message)), skipped: 'region mismatch: AWS was not contacted' });
  }

  const aws = governancePlanningAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).filter((_, i, all) => all[i - 1] !== '--template-body').join(' ')) });
  const caller = await callerIdentity(aws);
  base.target.caller = { arn: caller.arn, account: caller.account, kind: caller.kind };
  const identity = [accountCheck(caller, account), principalCheck(caller)].filter((c) => c.status === FAIL);
  if (identity.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: identity.flatMap((c) => c.findings.map((f) => finding(FAIL, f.kind, f.message))), skipped: 'identity check failed: nothing was read and no change set was created' });
  }
  const ctx = { aws, operator, environment, slug: null, account, region: resolved.region, partition: caller.partition };

  const stackName = BREAK_GLASS_GOVERNANCE_STACKS[environment];
  const unit = { stackKind: breakGlassGovernanceStackKind(environment), scope, stackName, label: `Break-glass governance stack (${environment})`, mode: 'planned', findings: [], checks: [], resources: [], iam: [], template: null, policies: {}, residual: [] };
  unit.checks.push({ id: 'admission', title: 'Allowed framework commits admissible', observed: admission.observed.length > 0 ? admission.observed : ['no commit listed: the parameter admits nothing'], findings: [] });
  unit.record = { admission: { environment, shas: [...policy.allowedFrameworkShas], originMain: admission.originMain } };

  const stackResources = await stackState(ctx, unit, { stackName, scope });
  const name = breakGlassNames(environment).frameworkPolicyParameter;
  const discovered = await discoverParameter(aws, name);
  const evaluated = await evaluateResource(ctx, {
    label: 'Allowed framework commits parameter',
    logicalId: GOVERNANCE_LOGICAL_ID,
    mode: 'managed',
    discovered,
    physicalId: name,
    type: 'AWS::SSM::Parameter',
    tags: null,
    stackName,
    scope,
    inStack: stackResources.some((r) => r.logicalId === GOVERNANCE_LOGICAL_ID)
  });
  unit.resources.push({ ...evaluated, discovered });
  unit.findings.push(...evaluated.findings);

  unit.residual.push(
    'Retain: deleting this stack or the resource revokes nothing. To revoke, plan `allowedFrameworkShas: []` and apply.',
    `The shared stack ${breakGlassNames(environment).stack} must grant its execution roles ssm:GetParameter on exactly ${name} (Phase 3D shared-stack update); until then the broker admits nothing.`
  );
  if (unit.findings.some((f) => f.severity === FAIL)) {
    return report(base, { outcome: 'BLOCKED', units: [unit], skipped: 'a precondition failed: no change set was created' });
  }
  unit.template = renderGovernanceTemplate({ policy, environment }).template;
  return recordPlans({
    units: [unit],
    base,
    scope,
    tags: ssdTags({ scope, environment }),
    aws,
    account,
    region: resolved.region,
    caller,
    root,
    env,
    sleep,
    repository: null,
    configDigest: governanceDigestOf(operator, policy)
  });
}
