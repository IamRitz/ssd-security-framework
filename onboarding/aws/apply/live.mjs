// The LIVE half of `aws apply`, as pure decisions over what AWS returned:
//
//   compareChangeSet   the change set described now must be byte-for-byte (as
//                      canonical JSON) the one recorded in change-set.json.
//                      `aws plan` normalizes no field of that document, so
//                      neither does apply: ANY difference — id, stack, status,
//                      execution status, capabilities, parameters, tags,
//                      nested-stack / import flags, the change list, or a field
//                      that was not there before — refuses, and the plan must
//                      be recreated.
//   compareTemplate    the change set's own template (get-template
//                      --template-stage Original) must be template.json.
//   checkStack         time-of-check/time-of-use on the stack itself:
//                        UPDATE  the live stack is the recorded base revision —
//                                same stack id, status and LastUpdatedTime;
//                        CREATE  the live stack is the REVIEW_IN_PROGRESS
//                                placeholder this change set created — same
//                                stack id (and, when the plan was made against
//                                an existing placeholder, the same revision);
//                      ownership: an UPDATE's stack still carries the SSD
//                      ownership tags; a CREATE's reviewed change set carries
//                      them (its placeholder has none yet — see checkStack).
//   stackProgress      after execute-change-set: waiting, succeeded or failed.
//                      Success is ONLY the operation's own *_COMPLETE on the
//                      same stack id (for UPDATE, with a LastUpdatedTime newer
//                      than the base revision's); a rollback, a delete, a
//                      different stack or an unknown state is failure.
import { tagList } from '../discover/oidc-provider.mjs';
import { LIVE, stackTagProblems } from '../discover/stacks.mjs';
import { canonicalJson } from '../templates/common.mjs';
import { breakGlassEnvironmentOf } from '../stack-names.mjs';

const finding = (kind, message) => ({ kind, message });

// -> findings[]
export function compareChangeSet(recorded, live) {
  if (live?.ChangeSetId !== recorded.ChangeSetId) {
    return [finding('change-set-replaced', `describe-change-set returned change set ${live?.ChangeSetId ?? '(none)'}, not the recorded ${recorded.ChangeSetId}`)];
  }
  const findings = [];
  if (live.Status !== 'CREATE_COMPLETE' || live.ExecutionStatus !== 'AVAILABLE') {
    findings.push(finding('change-set-not-executable', `the change set is ${live.Status}/${live.ExecutionStatus}; only CREATE_COMPLETE/AVAILABLE is executed`));
  }
  const keys = [...new Set([...Object.keys(recorded), ...Object.keys(live)])].sort();
  const differ = keys.filter((key) => canonicalJson(recorded[key] ?? null) !== canonicalJson(live[key] ?? null) || Object.hasOwn(recorded, key) !== Object.hasOwn(live, key));
  if (differ.length > 0) {
    findings.push(finding('change-set-changed', `the live change set differs from the recorded one in: ${differ.join(', ')}`));
  }
  return findings;
}

// get-template returns a JSON template as a parsed document (or, from some CLI
// versions, as a string). -> findings[]
export function compareTemplate(templateText, response) {
  let body = response?.TemplateBody;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = null;
    }
  }
  if (!body || typeof body !== 'object' || canonicalJson(body) !== templateText) {
    return [finding('template-changed', "the change set's template is not the recorded template.json")];
  }
  return [];
}

// stack: discoverStackByName() result (present | absent; unverified is the
// caller's to handle). -> findings[]
export function checkStack({ record, stack, slug }) {
  const { plan, operation, binding } = record;
  const base = plan.baseStack;
  if (stack.state === 'absent') {
    return [finding('stack-missing', `stack ${binding.stackName} no longer exists: re-plan`)];
  }
  const st = stack.value;
  const findings = [];
  if (st.stackId !== binding.stackId) {
    findings.push(finding('stack-replaced', `stack ${binding.stackName} is now ${st.stackId}, not the recorded ${binding.stackId}: another stack occupies the name`));
  }
  if (st.name !== binding.stackName) {
    findings.push(finding('stack-replaced', `describe-stacks returned stack '${st.name}', not '${binding.stackName}'`));
  }
  const owner = { scope: plan.scope, slug, environment: breakGlassEnvironmentOf(plan.stackKind) };
  if (operation === 'CREATE') {
    // Observed AWS behaviour (Phase 3C live validation, 2026-10-05): the
    // REVIEW_IN_PROGRESS placeholder of a CREATE change set has NO tags.
    // CloudFormation keeps the tags on the change set and copies them onto the
    // stack only when that change set executes. Before execution, ownership is
    // therefore proven by the reviewed change set itself (here, and byte-for-
    // byte by compareChangeSet), and the placeholder by identity: same stack id
    // and name, REVIEW_IN_PROGRESS, unchanged revision.
    const changeSetTags = stackTagProblems(tagList(record.changeSet?.Tags), owner);
    if (changeSetTags.length > 0) {
      findings.push(finding('change-set-not-owned', `the reviewed CREATE change set does not carry the SSD ownership tags: ${changeSetTags.join('; ')}`));
    }
    // An untagged placeholder is the normal case. A tagged one must carry
    // exactly the SSD ownership tags: foreign tags mean it is not ours.
    if (st.tags.length > 0) {
      const placeholderTags = stackTagProblems(st.tags, owner);
      if (placeholderTags.length > 0) {
        findings.push(finding('stack-not-owned', `the CREATE placeholder ${binding.stackName} carries tags that are not the SSD ownership tags: ${placeholderTags.join('; ')}`));
      }
    }
    if (st.status !== 'REVIEW_IN_PROGRESS') {
      findings.push(finding('stack-changed', `the CREATE placeholder ${binding.stackName} is ${st.status}, not REVIEW_IN_PROGRESS: re-plan`));
    }
    if (base.state === 'present' && st.lastUpdatedTime !== (base.lastUpdatedTime ?? null)) {
      findings.push(finding('stack-changed', `the placeholder ${binding.stackName} changed since the plan (LastUpdatedTime ${st.lastUpdatedTime ?? 'none'}, recorded ${base.lastUpdatedTime ?? 'none'}): re-plan`));
    }
  } else {
    const tags = stackTagProblems(st.tags, owner);
    if (tags.length > 0) {
      findings.push(finding('stack-not-owned', `stack ${binding.stackName} no longer carries the SSD ownership tags: ${tags.join('; ')}`));
    }
    if (st.status !== base.stackStatus || st.lastUpdatedTime !== (base.lastUpdatedTime ?? null)) {
      findings.push(
        finding(
          'stack-changed',
          `stack ${binding.stackName} changed since the plan: now ${st.status} (LastUpdatedTime ${st.lastUpdatedTime ?? 'none'}), recorded ${base.stackStatus} (LastUpdatedTime ${base.lastUpdatedTime ?? 'none'}). The plan is stale: re-plan`
        )
      );
    }
    if (!LIVE.has(st.status)) {
      findings.push(finding('stack-changed', `stack ${binding.stackName} is ${st.status}: only a settled, successful stack is updated`));
    }
  }
  return findings;
}

export const SUCCESS = Object.freeze({ CREATE: 'CREATE_COMPLETE', UPDATE: 'UPDATE_COMPLETE' });

// live: { stackId, status, lastUpdatedTime } from describe-stacks after execute.
// -> { state: 'waiting' | 'succeeded' | 'failed', reason }
export function stackProgress({ record, live }) {
  const { operation, binding, plan } = record;
  const base = plan.baseStack;
  if (live.stackId !== binding.stackId) {
    return { state: 'failed', reason: `describe-stacks returned ${live.stackId}, not the executed stack ${binding.stackId}` };
  }
  const status = live.status;
  if (operation === 'CREATE' && status === 'REVIEW_IN_PROGRESS') {
    return { state: 'waiting', reason: 'execution not started yet' };
  }
  if (operation === 'UPDATE' && status === base.stackStatus && live.lastUpdatedTime === (base.lastUpdatedTime ?? null)) {
    return { state: 'waiting', reason: 'execution not started yet' };
  }
  if (typeof status === 'string' && status.endsWith('_IN_PROGRESS')) {
    return { state: 'waiting', reason: status };
  }
  if (status === SUCCESS[operation]) {
    return { state: 'succeeded', reason: status };
  }
  return { state: 'failed', reason: `stack reached ${status ?? 'an unknown state'}, not ${SUCCESS[operation]}` };
}
