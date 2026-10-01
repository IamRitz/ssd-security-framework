// Offline IAM policy-document primitives: parse, normalize, match.
//
// A deliberately SMALL subset of IAM semantics, used conservatively:
//   - documents are normalized to arrays (Statement, Action, Resource, values);
//   - action names match case-insensitively with IAM `*`/`?` wildcards;
//     resource ARNs match case-sensitively with the same wildcards;
//   - NotAction / NotResource / NotPrincipal are not evaluated: a statement
//     using them is `unsupported`, and callers treat unsupported as "cannot be
//     bounded", never as "grants nothing".
// This is POLICY DOCUMENT ANALYSIS. It does not see SCPs, permission
// boundaries, resource policies, session policies or VPC endpoint policies.

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
  }
}

const list = (value) => (value === undefined || value === null ? [] : Array.isArray(value) ? value : [value]);

// A policy document as IAM returns it: an object, a JSON string, or a
// URL-encoded JSON string (IAM's wire form). Anything else is malformed.
export function parseDocument(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value;
  }
  if (typeof value !== 'string') {
    throw new PolicyError('policy document is neither an object nor a string');
  }
  for (const candidate of [value, safeDecode(value)]) {
    if (candidate === null) {
      continue;
    }
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch {
      // try the next form
    }
  }
  throw new PolicyError('policy document is not valid JSON');
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

// Document -> [{ sid, effect, principal, actions, resources, condition, unsupported[] }].
export function statements(document) {
  const doc = parseDocument(document);
  return list(doc.Statement).map((raw, index) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { sid: `#${index}`, effect: null, principal: null, actions: [], resources: [], condition: {}, unsupported: ['statement is not an object'] };
    }
    const unsupported = [];
    for (const key of ['NotAction', 'NotResource', 'NotPrincipal']) {
      if (raw[key] !== undefined) {
        unsupported.push(`${key} is not evaluated offline`);
      }
    }
    const effect = raw.Effect === 'Allow' || raw.Effect === 'Deny' ? raw.Effect : null;
    if (!effect) {
      unsupported.push(`Effect '${String(raw.Effect)}' is not Allow or Deny`);
    }
    const condition = raw.Condition === undefined ? {} : raw.Condition;
    if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
      unsupported.push('Condition is not an object');
    }
    return {
      sid: typeof raw.Sid === 'string' ? raw.Sid : `#${index}`,
      effect,
      principal: raw.Principal ?? null,
      actions: list(raw.Action).map(String),
      resources: list(raw.Resource).map(String),
      condition: condition && typeof condition === 'object' && !Array.isArray(condition) ? condition : {},
      unsupported
    };
  });
}

// IAM wildcard pattern -> RegExp. `*` any run, `?` one character.
function globRegExp(pattern, flags) {
  const body = String(pattern)
    .split('')
    .map((ch) => (ch === '*' ? '.*' : ch === '?' ? '.' : ch.replace(/[\\^$.|+()[\]{}]/g, '\\$&')))
    .join('');
  return new RegExp(`^${body}$`, flags);
}

export const hasWildcard = (value) => /[*?]/.test(String(value));

export const actionMatches = (pattern, action) => globRegExp(pattern, 'i').test(action);
export const resourceMatches = (pattern, resource) => globRegExp(pattern, '').test(resource);

// Principal -> { federated[], aws[], service[], any: boolean, other[] }.
export function principals(principal) {
  const out = { federated: [], aws: [], service: [], any: false, other: [] };
  if (principal === '*') {
    out.any = true;
    return out;
  }
  if (!principal || typeof principal !== 'object' || Array.isArray(principal)) {
    out.other.push(String(principal));
    return out;
  }
  for (const [key, value] of Object.entries(principal)) {
    const values = list(value).map(String);
    if (key === 'Federated') {
      out.federated.push(...values);
    } else if (key === 'AWS') {
      if (values.includes('*')) {
        out.any = true;
      }
      out.aws.push(...values.filter((v) => v !== '*'));
    } else if (key === 'Service') {
      out.service.push(...values);
    } else {
      out.other.push(`${key}:${values.join(',')}`);
    }
  }
  return out;
}

// Condition object -> [{ operator, key, values[] }], keys lower-cased (IAM
// condition keys are case-insensitive), operators verbatim.
export function conditionEntries(condition) {
  const out = [];
  for (const [operator, block] of Object.entries(condition ?? {})) {
    if (!block || typeof block !== 'object' || Array.isArray(block)) {
      out.push({ operator, key: null, values: [], malformed: true });
      continue;
    }
    for (const [key, value] of Object.entries(block)) {
      out.push({ operator, key: key.toLowerCase(), values: list(value).map(String) });
    }
  }
  return out;
}

// Does this set of identity-policy statements grant `action` on `resource`?
//   'allowed'      an unconditional Allow matches and no Deny matches
//   'conditional'  only an Allow carrying a Condition matches (not evaluated)
//   'denied'       an explicit Deny matches (conditions ignored: conservative)
//   'unsupported'  a statement that could matter uses NotAction/NotResource
//   'not-granted'  nothing matches
// Returns { decision, by: [sid...] }.
export function grants(stmts, action, resource) {
  const matching = (s) => s.actions.some((a) => actionMatches(a, action)) && s.resources.some((r) => resourceMatches(r, resource));
  const denies = stmts.filter((s) => s.effect === 'Deny' && s.unsupported.length === 0 && matching(s));
  if (denies.length > 0) {
    return { decision: 'denied', by: denies.map((s) => s.sid) };
  }
  const unsupported = stmts.filter((s) => s.unsupported.length > 0);
  const allows = stmts.filter((s) => s.effect === 'Allow' && s.unsupported.length === 0 && matching(s));
  const unconditional = allows.filter((s) => Object.keys(s.condition).length === 0);
  if (unconditional.length > 0 && unsupported.length === 0) {
    return { decision: 'allowed', by: unconditional.map((s) => s.sid) };
  }
  if (unsupported.length > 0) {
    return { decision: 'unsupported', by: unsupported.map((s) => s.sid) };
  }
  if (allows.length > 0) {
    return { decision: 'conditional', by: allows.map((s) => s.sid) };
  }
  return { decision: 'not-granted', by: [] };
}
