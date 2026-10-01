// A SEMANTIC diff of two IAM policy documents, for plan review.
//
// CloudFormation's change summary only says "AWS::IAM::Role Modify"; an
// operator needs to see what the trust or the permissions actually gain or
// lose. Documents are reduced to sets — so key order, statement order, Sid
// changes and string-vs-array spellings are not differences — and compared
// dimension by dimension:
//
//   principals   Federated / AWS / Service principals (and Principal "*")
//   subjects     token.actions.githubusercontent.com:sub values, with operator
//   audiences    token.actions.githubusercontent.com:aud values, with operator
//   actions      Effect + action (lower-cased: IAM actions are case-insensitive)
//   resources    Effect + resource ARN
//   grants       Effect + action + resource, the precise combination
//   conditions   every other condition operator/key/value
//
// An empty `before` (null) means the document is new: everything is added.
import { GITHUB_OIDC_HOST } from './trust.mjs';
import { conditionEntries, principals, statements } from './evaluate.mjs';

const SUB = `${GITHUB_OIDC_HOST}:sub`;
const AUD = `${GITHUB_OIDC_HOST}:aud`;

export const DIMENSIONS = Object.freeze(['principals', 'subjects', 'audiences', 'actions', 'resources', 'grants', 'conditions']);

// Document -> { principals: Set, subjects: Set, … } of canonical strings.
export function policyFacts(document) {
  const facts = Object.fromEntries(DIMENSIONS.map((d) => [d, new Set()]));
  if (document === null || document === undefined) {
    return facts;
  }
  for (const s of statements(document)) {
    const effect = s.effect ?? 'Unknown';
    if (s.principal !== null) {
      const p = principals(s.principal);
      if (p.any) facts.principals.add(`${effect} *`);
      p.federated.forEach((v) => facts.principals.add(`${effect} Federated ${v}`));
      p.aws.forEach((v) => facts.principals.add(`${effect} AWS ${v}`));
      p.service.forEach((v) => facts.principals.add(`${effect} Service ${v}`));
      p.other.forEach((v) => facts.principals.add(`${effect} ${v}`));
    }
    const actions = [...s.actions.map((a) => a.toLowerCase()), ...s.notActions.map((a) => `NOT ${a.toLowerCase()}`)];
    const resources = [...s.resources, ...s.notResources.map((r) => `NOT ${r}`)];
    actions.forEach((a) => facts.actions.add(`${effect} ${a}`));
    resources.forEach((r) => facts.resources.add(`${effect} ${r}`));
    for (const a of actions) {
      for (const r of resources.length > 0 ? resources : ['(no resource)']) {
        facts.grants.add(`${effect} ${a} on ${r}`);
      }
    }
    for (const entry of conditionEntries(s.condition)) {
      for (const value of entry.values) {
        const line = `${effect} ${entry.operator} ${value}`;
        if (entry.key === SUB) facts.subjects.add(line);
        else if (entry.key === AUD) facts.audiences.add(line);
        else facts.conditions.add(`${effect} ${entry.operator} ${entry.key} = ${value}`);
      }
    }
  }
  return facts;
}

const sorted = (set) => [...set].sort();

// -> { changed, created, dimensions: { principals: { added[], removed[] }, … } }
export function semanticPolicyDiff(before, after) {
  const a = policyFacts(before);
  const b = policyFacts(after);
  const dimensions = {};
  let changed = false;
  for (const d of DIMENSIONS) {
    const added = sorted(b[d]).filter((x) => !a[d].has(x));
    const removed = sorted(a[d]).filter((x) => !b[d].has(x));
    dimensions[d] = { added, removed };
    changed ||= added.length > 0 || removed.length > 0;
  }
  return { changed, created: before === null || before === undefined, dimensions };
}

// Human lines: "+ subject StringEquals repo:acme/app:ref:refs/heads/main".
const SINGULAR = { principals: 'principal', subjects: 'subject', audiences: 'audience', actions: 'action', resources: 'resource', grants: 'grant', conditions: 'condition' };
// `grants` lines are shown only for a grant change the action and resource
// lines do not already explain — e.g. an action moved from the configured
// repository to "*" while both sets stay the same — so a widening is never
// hidden and a new role is not listed twice.
export function diffLines(diff, { dimensions = ['principals', 'subjects', 'audiences', 'actions', 'resources', 'grants', 'conditions'] } = {}) {
  const lines = [];
  const touched = (list) => new Set([...list.added, ...list.removed]);
  const actions = touched(diff.dimensions.actions);
  const resources = touched(diff.dimensions.resources);
  const explained = (grant) => {
    const [effect, action, , ...resource] = grant.split(' ');
    return actions.has(`${effect} ${action}`) || resources.has(`${effect} ${resource.join(' ')}`);
  };
  // A NEW permission document is shown as its grants: action on resource is
  // the whole meaning, and separate action / resource lists would hide which
  // action reaches which resource.
  const shown = diff.created && dimensions.includes('grants') ? dimensions.filter((d) => d !== 'actions' && d !== 'resources') : dimensions;
  for (const d of shown) {
    const keep = d === 'grants' && !diff.created ? (x) => !explained(x) : () => true;
    diff.dimensions[d].removed.filter(keep).forEach((x) => lines.push(`- ${SINGULAR[d]} ${x}`));
    diff.dimensions[d].added.filter(keep).forEach((x) => lines.push(`+ ${SINGULAR[d]} ${x}`));
  }
  return lines;
}
