// `ssd-onboard aws plan --scope break-glass --environment <env>` (Phase 3C):
// one UNEXECUTED change set for one shared break-glass stack
// (ssd-break-glass-production | ssd-break-glass-synthetic).
//
// Same contract as every other plan (plan.mjs): breakGlassPlanningAws() only —
// the planning allowlist with its change-set calls confined to the two
// break-glass stacks, plus break-glass metadata reads — so nothing
// here can execute a change set, create a resource or upload anything; the
// plan directory is written through the same recordPlans() (scope assertion,
// persisted-secret check, plan id, exclusive writes). Apply then executes
// exactly that reviewed change set.
//
// Order is part of the contract; each step blocks before the next:
//   1. the framework checkout is bound to the operator config's
//      framework.ref (the Phase 2 rule) — AWS is not contacted otherwise;
//   2. region (--region > aws.region; a disagreeing flag blocks);
//   3. sts get-caller-identity: the configured account, never root;
//   4. the stack: absent, an ssd-onboard placeholder, or a settled stack
//      tagged for THIS environment (a synthetic-tagged stack is never the
//      production owner, and the reverse);
//   5. every named resource: absent, or a physical resource of exactly this
//      stack. A resource that merely has the name — including one owned by the
//      OTHER environment's stack — blocks (never adopted);
//   6. the artifact: the configured object version exists in a private,
//      versioned bucket (break-glass/artifact.mjs);
//   7. render; the two execution roles' trust/permission diffs; then
//      recordPlans().
import { breakGlassPlanningAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { discoverRole } from '../discover/iam-role.mjs';
import { PlanError, evaluateResource, iamRecord, recordPlans, report, stackState } from '../plan.mjs';
import { BREAK_GLASS_ENVIRONMENTS, BREAK_GLASS_STACKS, breakGlassStackKind } from '../stack-names.mjs';
import { ssdTags } from '../templates/common.mjs';
import { BREAK_GLASS_LOGICAL_IDS as L, renderBreakGlassTemplate } from '../templates/shared-break-glass.mjs';
import { frameworkProblems } from '../../lib/framework.mjs';
import { artifactFindings } from './artifact.mjs';
import { discoverArtifact, discoverFunction, discoverLogGroup, discoverSecret, discoverTable } from './discover.mjs';
import { breakGlassArns, breakGlassNames } from './names.mjs';
import { operatorDigestOf } from './operator-config.mjs';

const FAIL = 'FAIL';
const finding = (severity, kind, message) => ({ severity, kind, message });

// The named resources a break-glass stack creates, how to look each up, and
// its CloudFormation physical id.
function namedResources(environment, target) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, target);
  const physical = (r) => (r.state === 'present' ? r.value.name : null);
  return [
    { label: 'DynamoDB table', logicalId: L.table, type: 'AWS::DynamoDB::Table', name: n.table, discover: (aws) => discoverTable(aws, n.table), physical },
    { label: 'Slack bot token secret', logicalId: L.slackBotToken, type: 'AWS::SecretsManager::Secret', name: n.secrets.slackBotToken, discover: (aws) => discoverSecret(aws, n.secrets.slackBotToken), physical: (r) => (r.state === 'present' ? r.value.arn : null) },
    { label: 'Slack signing secret', logicalId: L.slackSigningSecret, type: 'AWS::SecretsManager::Secret', name: n.secrets.slackSigningSecret, discover: (aws) => discoverSecret(aws, n.secrets.slackSigningSecret), physical: (r) => (r.state === 'present' ? r.value.arn : null) },
    { label: 'GitHub token secret', logicalId: L.githubToken, type: 'AWS::SecretsManager::Secret', name: n.secrets.githubToken, discover: (aws) => discoverSecret(aws, n.secrets.githubToken), physical: (r) => (r.state === 'present' ? r.value.arn : null) },
    { label: 'CI log group', logicalId: L.ciLogGroup, type: 'AWS::Logs::LogGroup', name: n.logGroups.ci, discover: (aws) => discoverLogGroup(aws, n.logGroups.ci), physical },
    { label: 'Interaction log group', logicalId: L.interactionsLogGroup, type: 'AWS::Logs::LogGroup', name: n.logGroups.interactions, discover: (aws) => discoverLogGroup(aws, n.logGroups.interactions), physical },
    { label: 'CI execution role', logicalId: L.ciRole, type: 'AWS::IAM::Role', name: n.roles.ci, arn: a.roles.ci, role: 'ci', discover: (aws) => discoverRole(aws, a.roles.ci), physical },
    { label: 'Interaction execution role', logicalId: L.interactionsRole, type: 'AWS::IAM::Role', name: n.roles.interactions, arn: a.roles.interactions, role: 'interactions', discover: (aws) => discoverRole(aws, a.roles.interactions), physical },
    { label: 'CI broker function', logicalId: L.ciFunction, type: 'AWS::Lambda::Function', name: n.functions.ci, discover: (aws) => discoverFunction(aws, n.functions.ci), physical },
    { label: 'Interaction function', logicalId: L.interactionsFunction, type: 'AWS::Lambda::Function', name: n.functions.interactions, discover: (aws) => discoverFunction(aws, n.functions.interactions), physical }
  ];
}

async function prepareBreakGlassUnit(ctx) {
  const { environment, operator } = ctx;
  const stackName = BREAK_GLASS_STACKS[environment];
  const unit = { stackKind: breakGlassStackKind(environment), scope: 'break-glass', stackName, label: `Shared break-glass stack (${environment})`, mode: 'planned', findings: [], checks: [], resources: [], iam: [], template: null, policies: {}, residual: [] };
  const target = { partition: ctx.partition, account: ctx.account, region: ctx.region };

  const stackResources = await stackState(ctx, unit, { stackName, scope: 'break-glass' });
  const inStack = (logicalId) => stackResources.some((r) => r.logicalId === logicalId);

  for (const spec of namedResources(environment, target)) {
    const discovered = await spec.discover(ctx.aws);
    if (spec.role && discovered.state === 'present' && discovered.value.arn !== spec.arn) {
      unit.findings.push(finding(FAIL, 'role-name-collision', `${spec.label}: a role named like ${spec.name} exists as ${discovered.value.arn ?? '(no ARN)'}, not ${spec.arn} (IAM role names are case-insensitive)`));
      continue;
    }
    const evaluated = await evaluateResource(ctx, {
      label: spec.label,
      logicalId: spec.logicalId,
      mode: 'managed',
      discovered,
      physicalId: spec.physical(discovered) ?? spec.name,
      type: spec.type,
      tags: spec.role && discovered.state === 'present' ? discovered.value.tags : null,
      stackName,
      scope: 'break-glass',
      inStack: inStack(spec.logicalId)
    });
    unit.resources.push({ ...evaluated, discovered, key: spec.role ?? null, arn: spec.arn ?? null });
    unit.findings.push(...evaluated.findings);
  }

  const artifact = operator.environments[environment].artifact;
  const art = artifactFindings(await discoverArtifact(ctx.aws, artifact), artifact);
  unit.findings.push(...art.findings);
  unit.checks.push({ id: 'artifact', title: 'Published Lambda artifact', observed: art.observed, findings: art.findings });

  unit.residual.push(
    'Secret values are never planned: after apply, put each secret value out of band (aws secretsmanager put-secret-value --secret-string file:///dev/stdin); until then the broker cannot start (fail closed).',
    'The Slack Request URL of this environment\'s Slack app is set by hand to the interaction function\'s Function URL after apply.',
    'Per-repository invoker roles and approver parameters are not part of this stack (Phase 3D).'
  );

  if (unit.findings.some((f) => f.severity === FAIL)) {
    return unit;
  }
  const rendered = renderBreakGlassTemplate({ operator, environment, partition: ctx.partition });
  unit.template = rendered.template;
  const n = breakGlassNames(environment);
  for (const [logicalId, generated] of Object.entries(rendered.policies)) {
    const resource = unit.resources.find((r) => r.logicalId === logicalId) ?? { owned: false };
    const record = await iamRecord(ctx, { key: generated.role, arn: generated.arn, logicalId, generated, resource, stackName, policyName: n.rolePolicies[generated.role] });
    unit.iam.push(record);
    unit.findings.push(...record.findings);
  }
  return unit;
}

// awsPlanBreakGlass(options) -> report (the aws plan report shape). Throws for
// a run-ending failure, like awsPlan.
//   operator     the validated operator config     environment  production | synthetic
//   framework    detectFramework() result          root         where .ssd/aws-plans/ is written
//   region / exec / env / deadlineMs / now / sleep   as awsPlan
export async function awsPlanBreakGlass({ operator, environment, region: explicitRegion = null, exec, env = process.env, framework, root, deadlineMs, now, sleep }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
    throw new PlanError('unsupported-environment', `--environment must be production or synthetic (got '${environment}')`);
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
  const regionC = regionCheck(resolved);
  if (regionC.status === FAIL) {
    return report(base, { outcome: 'BLOCKED', findings: regionC.findings.map((f) => finding(FAIL, f.kind, f.message)), skipped: 'region mismatch: AWS was not contacted' });
  }

  const aws = breakGlassPlanningAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).filter((_, i, all) => all[i - 1] !== '--template-body').join(' ')) });
  const caller = await callerIdentity(aws);
  base.target.caller = { arn: caller.arn, account: caller.account, kind: caller.kind };
  const identity = [accountCheck(caller, account), principalCheck(caller)].filter((c) => c.status === FAIL);
  if (identity.length > 0) {
    return report(base, { outcome: 'BLOCKED', findings: identity.flatMap((c) => c.findings.map((f) => finding(FAIL, f.kind, f.message))), skipped: 'identity check failed: nothing was read and no change set was created' });
  }
  const ctx = { aws, operator, environment, slug: null, account, region: resolved.region, partition: caller.partition };
  const units = [await prepareBreakGlassUnit(ctx)];
  if (units.some((u) => u.findings.some((f) => f.severity === FAIL))) {
    return report(base, { outcome: 'BLOCKED', units, skipped: 'a precondition failed: no change set was created' });
  }
  return recordPlans({
    units,
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
    configDigest: operatorDigestOf(operator)
  });
}
