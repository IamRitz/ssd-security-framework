// Offline evaluation of a GitHub OIDC role trust policy.
//
// The question is not "does the policy mention GitHub" but: WHICH GitHub
// workflow runs can assume this role? The answer is acceptable only when every
// trust path is bounded to this repository and the role's intended context:
//
//   push+scan  ref:refs/heads/<default branch>
//   deploy     environment:<delivery.environment>
//
// Understood: Principal.Federated, sts:AssumeRoleWithWebIdentity, and the
// StringEquals / StringLike operators over token.actions.githubusercontent.com
// :aud and :sub. Everything else is treated conservatively:
//   - an unsupported operator (StringNotEquals, ForAnyValue:…, …IfExists, …) or
//     NotPrincipal/NotAction is FAIL: the evaluator cannot bound it;
//   - a supported operator over another key only narrows access, so it is a
//     WARN (not evaluated), never a reason to accept;
//   - any `*` or `?` in a subject is FAIL: it admits runs this role is not for;
//   - StringLike with an exact value is equivalent but WARNs: generated trust
//     uses StringEquals;
//   - a Deny statement only narrows: WARN (not evaluated).
// Subject formats: legacy `repo:<owner>/<repo>:<context>` is compared exactly.
// The immutable customization `repo:<owner>@<id>/<repo>@<id>:<context>` is
// accepted with a WARN: the IDs cannot be proven to be this repository's
// without the GitHub API (a later, explicit integration).
import { actionMatches, conditionEntries, hasWildcard, principals, resourceMatches, statements } from './evaluate.mjs';

export const GITHUB_OIDC_HOST = 'token.actions.githubusercontent.com';
export const STS_AUDIENCE = 'sts.amazonaws.com';
const AUD_KEY = `${GITHUB_OIDC_HOST}:aud`;
const SUB_KEY = `${GITHUB_OIDC_HOST}:sub`;
const SUPPORTED_OPERATORS = new Set(['StringEquals', 'StringLike']);
const WEB_IDENTITY = 'sts:AssumeRoleWithWebIdentity';
const ASSUME_ACTIONS = ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity', 'sts:AssumeRoleWithSAML'];

export const providerArn = (account, partition = 'aws') => `arn:${partition}:iam::${account}:oidc-provider/${GITHUB_OIDC_HOST}`;

// The contexts a role is for. `environment` '' means the deploy job has no
// GitHub environment, so its token carries the branch context instead.
export function intendedContexts(role, { defaultBranch, environment }) {
  if (role === 'deploy' && environment) {
    return [`environment:${environment}`];
  }
  return [`ref:refs/heads/${defaultBranch}`];
}

const SUBJECT = /^repo:([^:]+):(.+)$/;
const IMMUTABLE_REPO = /^([^@/]+)@(\d+)\/([^@/]+)@(\d+)$/;

// One exact subject value -> { value, format, context, expected, findings[] }.
export function classifySubject(value, { slug, contexts }) {
  const out = { value, format: null, context: null, expected: false, findings: [] };
  const match = SUBJECT.exec(value);
  if (!match) {
    out.findings.push({ severity: 'FAIL', kind: 'unexpected-subject', message: `subject '${value}' is not a GitHub repository subject` });
    return out;
  }
  const [, repo, context] = match;
  out.context = context;
  const [owner, name] = slug.split('/');
  const immutable = IMMUTABLE_REPO.exec(repo);
  let repoOk = false;
  if (immutable) {
    out.format = 'immutable';
    if (immutable[1].toLowerCase() === owner.toLowerCase() && immutable[3].toLowerCase() === name.toLowerCase()) {
      repoOk = true;
      out.findings.push({
        severity: 'WARN',
        kind: 'immutable-ids-unverified',
        message: `subject '${value}' uses the immutable format; owner id ${immutable[2]} and repository id ${immutable[4]} are NOT VERIFIED as ${slug}'s without the GitHub API`
      });
    }
  } else {
    out.format = 'legacy';
    if (repo === slug) {
      repoOk = true;
    } else if (repo.toLowerCase() === slug.toLowerCase()) {
      repoOk = true;
      out.findings.push({ severity: 'WARN', kind: 'subject-case', message: `subject '${value}' differs from repository.slug ${slug} only in case (StringEquals is case-sensitive; GitHub sends the canonical case)` });
    }
  }
  if (!repoOk) {
    out.findings.push({ severity: 'FAIL', kind: 'wrong-repository', message: `subject '${value}' admits another repository (expected ${slug})` });
  }
  const contextOk = contexts.includes(context);
  if (!contextOk) {
    const kind = context === 'pull_request'
      ? 'pull-request-context'
      : context.startsWith('ref:refs/heads/')
        ? 'wrong-branch'
        : context.startsWith('environment:')
          ? 'wrong-environment'
          : 'wrong-context';
    out.findings.push({ severity: 'FAIL', kind, message: `subject '${value}' admits context '${context}' (expected ${contexts.join(' or ')})` });
  }
  out.expected = repoOk && contextOk;
  return out;
}

// A wildcard subject pattern: always FAIL, named by what it opens up.
function wildcardSubject(pattern, { slug }) {
  const owner = slug.split('/')[0];
  let kind = 'wildcard-subject';
  if (/^[*?]+$/.test(pattern) || pattern === 'repo:*') {
    kind = 'any-repository';
  } else if (new RegExp(`^repo:${owner.replace(/[\\^$.|+()[\]{}]/g, '\\$&')}(?:@[^/]*)?/[*?]`, 'i').test(pattern)) {
    kind = 'organization-wide';
  }
  return { severity: 'FAIL', kind, message: `subject pattern '${pattern}' is a wildcard (${kind.replace(/-/g, ' ')}); only exact subjects are acceptable` };
}

// Does `value` satisfy one condition entry?
function satisfies(entry, value) {
  return entry.operator === 'StringEquals' ? entry.values.includes(value) : entry.values.some((pattern) => resourceMatches(pattern, value));
}

// One condition key's entries -> { bounded, findings, exactValues }.
// Bounded: some entry restricts the key to exact, acceptable values (entries
// are ANDed, so one bounding entry bounds the key). `accept(value)` returns the
// findings for one exact value (FAIL ones make it unacceptable).
function boundKey(entries, keyLabel, accept, { wildcard }) {
  const findings = [];
  const perEntry = entries.map((entry) => {
    const entryFindings = [];
    let acceptable = true;
    for (const value of entry.values) {
      if (entry.operator === 'StringLike' && hasWildcard(value)) {
        entryFindings.push(wildcard(value));
        acceptable = false;
        continue;
      }
      const valueFindings = accept(value);
      entryFindings.push(...valueFindings);
      if (valueFindings.some((f) => f.severity === 'FAIL')) {
        acceptable = false;
      }
    }
    if (entry.values.length === 0) {
      acceptable = false;
      entryFindings.push({ severity: 'FAIL', kind: 'empty-condition', message: `${entry.operator} ${keyLabel} lists no values` });
    }
    return { entry, acceptable, findings: entryFindings };
  });
  const bounding = perEntry.filter((p) => p.acceptable);
  if (bounding.length === 0) {
    perEntry.forEach((p) => findings.push(...p.findings));
    return { bounded: false, findings };
  }
  for (const p of bounding) {
    findings.push(...p.findings);
    if (p.entry.operator === 'StringLike') {
      findings.push({ severity: 'WARN', kind: 'stringlike-exact', message: `StringLike on ${keyLabel} with exact values; generated trust uses StringEquals` });
    }
  }
  // Non-bounding entries are ANDed with a bounding one: they can only narrow.
  for (const p of perEntry.filter((q) => !q.acceptable)) {
    findings.push({ severity: 'WARN', kind: 'narrowing-condition', message: `${p.entry.operator} ${keyLabel} [${p.entry.values.join(', ')}] only narrows an exact condition; not evaluated further` });
  }
  return { bounded: true, findings };
}

// A statement that trusts the expected provider -> { bounded, reachable, findings, subjects }.
function evaluateOidcStatement(stmt, { slug, contexts }) {
  const findings = [];
  const entries = conditionEntries(stmt.condition);
  const aud = [];
  const sub = [];
  for (const entry of entries) {
    if (entry.malformed) {
      findings.push({ severity: 'FAIL', kind: 'unsupported-condition', message: `condition operator ${entry.operator} is malformed` });
      continue;
    }
    if (!SUPPORTED_OPERATORS.has(entry.operator)) {
      findings.push({ severity: 'FAIL', kind: 'unsupported-condition', message: `condition ${entry.operator} on ${entry.key} is not evaluated offline; treated as unbounded` });
      continue;
    }
    if (entry.key === AUD_KEY) {
      aud.push(entry);
    } else if (entry.key === SUB_KEY) {
      sub.push(entry);
    } else {
      findings.push({ severity: 'WARN', kind: 'condition-not-evaluated', message: `${entry.operator} on ${entry.key} is not evaluated (it can only narrow access)` });
    }
  }

  let audBounded = false;
  if (aud.length === 0) {
    findings.push({ severity: 'FAIL', kind: 'audience-unconstrained', message: `no ${AUD_KEY} condition: a token for any audience is accepted` });
  } else {
    const result = boundKey(
      aud,
      AUD_KEY,
      (value) => (value === STS_AUDIENCE ? [] : [{ severity: 'FAIL', kind: 'wrong-audience', message: `audience '${value}' is accepted (expected only ${STS_AUDIENCE})` }]),
      { wildcard: (value) => ({ severity: 'FAIL', kind: 'wrong-audience', message: `audience pattern '${value}' is a wildcard (expected exactly ${STS_AUDIENCE})` }) }
    );
    audBounded = result.bounded;
    findings.push(...result.findings);
  }

  const subjects = [];
  let subBounded = false;
  if (sub.length === 0) {
    findings.push({ severity: 'FAIL', kind: 'subject-unconstrained', message: `no ${SUB_KEY} condition: ANY GitHub repository's workflow can assume this role` });
  } else {
    const result = boundKey(
      sub,
      SUB_KEY,
      (value) => {
        const classified = classifySubject(value, { slug, contexts });
        subjects.push(classified);
        return classified.findings;
      },
      { wildcard: (value) => wildcardSubject(value, { slug }) }
    );
    subBounded = result.bounded;
    findings.push(...result.findings);
  }

  // Reachable: an intended subject satisfies EVERY sub and aud entry.
  const [owner, name] = slug.split('/');
  const candidates = [
    ...contexts.map((context) => `repo:${owner}/${name}:${context}`),
    ...subjects.filter((s) => s.expected).map((s) => s.value)
  ];
  const reachable = candidates.some((candidate) => sub.every((entry) => satisfies(entry, candidate))) && aud.every((entry) => satisfies(entry, STS_AUDIENCE));
  return { bounded: audBounded && subBounded, reachable, findings, subjects };
}

const accountOf = (principal) => /^\d{12}$/.test(principal) ? principal : /^arn:[^:]+:iam::(\d{12}):/.exec(principal)?.[1] ?? null;

// evaluateTrust(document, { account, partition, slug, contexts })
//   -> { verdict, findings[], subjects[], format, reachable }
// verdict: 'accepted' | 'accepted-with-warnings' | 'rejected'.
export function evaluateTrust(document, { account, partition = 'aws', slug, contexts }) {
  const expectedProvider = providerArn(account, partition);
  const findings = [];
  const subjects = [];
  let trustsProvider = false;
  let reachable = false;
  let stmts;
  try {
    stmts = statements(document);
  } catch (error) {
    return { verdict: 'rejected', findings: [{ severity: 'FAIL', kind: 'malformed-policy', message: error.message }], subjects: [], format: null, reachable: false };
  }
  for (const stmt of stmts) {
    const tag = (f) => ({ ...f, sid: stmt.sid });
    if (stmt.unsupported.length > 0) {
      stmt.unsupported.forEach((message) =>
        findings.push(tag({ severity: stmt.effect === 'Deny' ? 'WARN' : 'FAIL', kind: 'unsupported-construct', message: `${message}; treated as unbounded` }))
      );
      continue;
    }
    if (stmt.effect === 'Deny') {
      findings.push(tag({ severity: 'WARN', kind: 'deny-not-evaluated', message: 'a Deny statement is not evaluated (it can only narrow access)' }));
      continue;
    }
    const assumes = ASSUME_ACTIONS.some((action) => stmt.actions.some((pattern) => actionMatches(pattern, action)));
    if (!assumes) {
      continue; // e.g. sts:TagSession alone grants no assumption
    }
    if (stmt.actions.some((pattern) => hasWildcard(pattern))) {
      findings.push(tag({ severity: 'WARN', kind: 'action-wildcard', message: `trust action [${stmt.actions.join(', ')}] is a wildcard; expected ${WEB_IDENTITY}` }));
    }
    const p = principals(stmt.principal);
    if (p.any) {
      findings.push(tag({ severity: 'FAIL', kind: 'any-principal', message: 'Principal "*": anyone can attempt to assume this role' }));
    }
    for (const principal of p.aws) {
      const principalAccount = accountOf(principal);
      findings.push(
        tag(
          principalAccount === account
            ? { severity: 'WARN', kind: 'additional-principal', message: `AWS principal ${principal} can also assume this role` }
            : { severity: 'FAIL', kind: 'cross-account-principal', message: `AWS principal ${principal} (account ${principalAccount ?? 'unknown'}) can assume this role` }
        )
      );
    }
    for (const service of p.service) {
      findings.push(tag({ severity: 'WARN', kind: 'additional-principal', message: `service principal ${service} can also assume this role` }));
    }
    for (const other of p.other) {
      findings.push(tag({ severity: 'FAIL', kind: 'unsupported-construct', message: `principal ${other} is not evaluated offline; treated as unbounded` }));
    }
    for (const federated of p.federated) {
      if (federated !== expectedProvider) {
        findings.push(tag({ severity: 'FAIL', kind: 'wrong-provider', message: `federated principal ${federated} is trusted (expected ${expectedProvider})` }));
        continue;
      }
      if (!stmt.actions.some((pattern) => actionMatches(pattern, WEB_IDENTITY))) {
        continue;
      }
      trustsProvider = true;
      const result = evaluateOidcStatement(stmt, { slug, contexts });
      findings.push(...result.findings.map(tag));
      subjects.push(...result.subjects);
      reachable ||= result.reachable && result.bounded;
    }
  }
  if (!trustsProvider) {
    findings.push({ severity: 'FAIL', kind: 'no-github-trust', message: `no statement lets ${expectedProvider} assume this role with ${WEB_IDENTITY}` });
  } else if (!reachable && !findings.some((f) => f.severity === 'FAIL')) {
    findings.push({ severity: 'FAIL', kind: 'intended-context-cannot-assume', message: `no trust statement admits the intended context (${contexts.join(' or ')})` });
  }
  const formats = [...new Set(subjects.filter((s) => s.expected).map((s) => s.format))];
  const verdict = findings.some((f) => f.severity === 'FAIL') ? 'rejected' : findings.length > 0 ? 'accepted-with-warnings' : 'accepted';
  return { verdict, findings, subjects, format: formats.length === 1 ? formats[0] : formats.length > 1 ? 'mixed' : null, reachable };
}

// --- builder (Phase 2B) --------------------------------------------------------------

export class TrustBuildError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TrustBuildError';
  }
}

// The ONE trust policy ssd-onboard generates for a delivery role:
//   Principal.Federated   exactly this account's GitHub OIDC provider
//   Action                sts:AssumeRoleWithWebIdentity
//   Condition             StringEquals aud = sts.amazonaws.com
//                         StringEquals sub = repo:<slug>:<intended context>
// Exact legacy subjects only: the immutable-ID format needs IDs this command
// cannot prove without the GitHub API, so it is never generated. No StringLike,
// no wildcard. The result must be ACCEPTED, without a single warning, by
// evaluateTrust() above — the same evaluator `aws doctor` applies — or nothing
// is generated.
export function buildTrustPolicy(role, { account, partition = 'aws', slug, defaultBranch, environment }) {
  const contexts = intendedContexts(role, { defaultBranch, environment });
  const subjects = contexts.map((context) => `repo:${slug}:${context}`);
  for (const value of [slug, ...subjects]) {
    if (hasWildcard(value)) {
      throw new TrustBuildError(`refusing to generate a trust policy with a wildcard subject ('${value}')`);
    }
  }
  const document = {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'GitHubActionsOidc',
        Effect: 'Allow',
        Principal: { Federated: providerArn(account, partition) },
        Action: WEB_IDENTITY,
        Condition: {
          StringEquals: {
            [AUD_KEY]: STS_AUDIENCE,
            [SUB_KEY]: subjects.length === 1 ? subjects[0] : subjects
          }
        }
      }
    ]
  };
  const evaluation = evaluateTrust(document, { account, partition, slug, contexts });
  if (evaluation.verdict !== 'accepted') {
    throw new TrustBuildError(`the generated ${role} trust policy is not accepted by the trust evaluator: ${evaluation.findings.map((f) => `${f.severity} ${f.kind}`).join(', ')}`);
  }
  return document;
}
