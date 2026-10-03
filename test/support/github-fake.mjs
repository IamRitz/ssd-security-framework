// A stateful fake of the GitHub CLI for the `ssd-onboard github` tests.
//
// exec(argv, { stdin, env }) behaves like gh: a 2xx answer prints JSON on
// stdout and exits 0; an error prints GitHub's error body on stdout and
// `gh: <message> (HTTP <status>)` on stderr and exits 1 (the shape observed
// live, test/fixtures/github/README.md). Every argv is checked INDEPENDENTLY
// against the wrapper's own allowlist (assertApplyArgv) plus the mutations the
// test permits; anything else is recorded in `unexpected` and refused.
//
// The world is derived, not scripted per call: rules for the branch are
// computed from the ruleset details (active, matching the branch), so a
// ruleset POSTed by apply is visible to the re-reads that follow.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { assertApplyArgv, rulesetArgv, secretArgv } from '../../onboarding/github/gh-cli.mjs';

const FIXTURES = join(import.meta.dirname, '..', 'fixtures', 'github');
export const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));

export const SLUG = 'acme/app';
export const BRANCH = 'main';
export const SECRET = 'SECURITY_NOTIFY_SLACK_URL';
export const REPO_ID = 4242;

const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

// The live repository shape, re-pointed at the fixture repository.
export function repositoryDoc(overrides = {}) {
  const live = fixture('live-repository.json');
  return { ...live, full_name: SLUG, id: REPO_ID, owner: { ...live.owner, login: 'acme' }, default_branch: BRANCH, ...overrides };
}

// A CODEOWNERS contents document for `text` at `path`.
export function contentsDoc(text, path = '.github/CODEOWNERS', extra = {}) {
  const bytes = Buffer.from(text, 'utf8');
  return { type: 'file', encoding: 'base64', size: bytes.length, name: path.split('/').pop(), path, sha: gitSha(text), content: `${bytes.toString('base64')}\n`, ...extra };
}
function gitSha(text) {
  const bytes = Buffer.from(text, 'utf8');
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

export const COMPLETE_CODEOWNERS = '/.ssd/ @acme/security\n/.github/workflows/ @acme/security\n/security/baseline/semgrep-baseline.json @acme/security\n/.semgrepignore @acme/security\n';

// A compliant repository ruleset (fixture doc-ruleset-detail.json) by default.
export function rulesetDetail(overrides = {}) {
  return { ...fixture('doc-ruleset-detail.json'), ...overrides };
}

// world: everything GitHub holds. Fields left out take a compliant-looking but
// EMPTY default (no rulesets, no protection, a complete CODEOWNERS).
export function githubWorld(spec = {}) {
  return {
    user: spec.user ?? { login: 'operator' },
    repository: spec.repository ?? repositoryDoc(),
    actionsApp: spec.actionsApp ?? fixture('live-actions-app.json'),
    secrets: clone(spec.secrets ?? []),
    rulesets: clone(spec.rulesets ?? []), // details
    hideBypass: new Set(spec.hideBypass ?? []), // ruleset ids whose bypass_actors GitHub omits
    detailErrors: spec.detailErrors ?? {}, // id -> { status, message }
    branchRules: spec.branchRules, // explicit override of the derived list
    protection: spec.protection ?? null, // classic protection document
    protectionError: spec.protectionError ?? null,
    contents: spec.contents ?? { '.github/CODEOWNERS': contentsDoc(COMPLETE_CODEOWNERS) },
    codeownersErrors: spec.codeownersErrors ?? { errors: [] },
    overrides: spec.overrides ?? {}, // endpoint (or 'secret set' / 'POST rulesets') -> response
    nextId: 1000,
    clock: 0
  };
}

const ok = (body) => ({ stdout: `${JSON.stringify(body)}\n`, stderr: '', exitCode: 0, error: null, timedOut: false, overflow: false });
export const httpError = (status, message) => ({
  stdout: `${JSON.stringify({ message, documentation_url: 'https://docs.github.com/rest', status: String(status) })}\n`,
  stderr: `gh: ${message} (HTTP ${status})\n`,
  exitCode: 1,
  error: null,
  timedOut: false,
  overflow: false
});
const respond = (spec) => {
  if (spec.timeout) return { stdout: '', stderr: '', exitCode: null, error: null, timedOut: true, overflow: false };
  if (spec.raw !== undefined) return { stdout: spec.raw, stderr: '', exitCode: 0, error: null, timedOut: false, overflow: false };
  if (spec.status) return httpError(spec.status, spec.message ?? 'error');
  return ok(spec.body);
};

function covers(detail, branch) {
  const include = detail.conditions?.ref_name?.include ?? [];
  const exclude = detail.conditions?.ref_name?.exclude ?? [];
  const hit = (p) => p === '~ALL' || p === '~DEFAULT_BRANCH' || p === `refs/heads/${branch}`;
  return include.some(hit) && !exclude.some(hit);
}

function branchRulesOf(world) {
  if (world.branchRules !== undefined) return world.branchRules;
  return world.rulesets
    .filter((d) => d.enforcement === 'active' && d.target === 'branch' && covers(d, BRANCH))
    .flatMap((d) => d.rules.map((r) => ({ type: r.type, ruleset_source_type: d.source_type ?? 'Repository', ruleset_source: d.source ?? SLUG, ruleset_id: d.id, ...(r.parameters ? { parameters: r.parameters } : {}) })));
}

const pageOf = (endpoint) => Number(/[?&]page=(\d+)/.exec(endpoint)?.[1] ?? 1);
const paginate = (list, page) => list.slice((page - 1) * 100, page * 100);

function route(world, endpoint) {
  const repo = `repos/${SLUG}`;
  const page = pageOf(endpoint);
  if (endpoint === 'user') return world.user.status ? respond(world.user) : ok(world.user);
  if (endpoint === 'apps/github-actions') return world.actionsApp.status ? respond(world.actionsApp) : ok(world.actionsApp);
  if (endpoint === repo) return world.repository.status ? respond(world.repository) : ok(world.repository);
  if (endpoint.startsWith(`${repo}/actions/secrets?`)) return ok({ total_count: world.secrets.length, secrets: paginate(world.secrets, page) });
  if (endpoint.startsWith(`${repo}/rules/branches/${BRANCH}?`)) return ok(paginate(branchRulesOf(world), page));
  if (endpoint.startsWith(`${repo}/rulesets?`)) {
    return ok(paginate(world.rulesets.map((d) => ({ id: d.id, name: d.name, target: d.target, source_type: d.source_type ?? 'Repository', source: d.source ?? SLUG, enforcement: d.enforcement, updated_at: d.updated_at })), page));
  }
  const detail = /^repos\/[^/]+\/[^/]+\/rulesets\/(\d+)\?includes_parents=true$/.exec(endpoint);
  if (detail) {
    const id = Number(detail[1]);
    if (world.detailErrors[id]) return respond(world.detailErrors[id]);
    const d = world.rulesets.find((r) => r.id === id);
    if (!d) return httpError(404, 'Not Found');
    const out = clone(d);
    if (world.hideBypass.has(id)) {
      delete out.bypass_actors;
      delete out.current_user_can_bypass;
    }
    return ok(out);
  }
  if (endpoint === `${repo}/branches/${BRANCH}`) {
    const live = fixture('live-branch-unprotected.json');
    return ok({ ...live, protected: world.protection !== null || world.protectionError !== null });
  }
  if (endpoint === `${repo}/branches/${BRANCH}/protection`) {
    if (world.protectionError) return respond(world.protectionError);
    return world.protection ? ok(world.protection) : httpError(404, 'Branch not protected');
  }
  const contents = new RegExp(`^${repo}/contents/(.+)\\?ref=${BRANCH}$`).exec(endpoint);
  if (contents) {
    const doc = world.contents[contents[1]];
    if (!doc) return httpError(404, 'Not Found');
    return doc.status ? respond(doc) : ok(doc);
  }
  if (endpoint === `${repo}/codeowners/errors?ref=${BRANCH}`) {
    const hasFile = Object.values(world.contents).some((d) => d && !d.status);
    if (!hasFile) return httpError(404, 'Not Found');
    return world.codeownersErrors.status ? respond(world.codeownersErrors) : ok(world.codeownersErrors);
  }
  return httpError(404, 'Not Found');
}

// mutations: which mutation argvs this test permits ('secret', 'ruleset').
export function githubFake(world, { mutations = ['secret', 'ruleset'], secretName = SECRET } = {}) {
  const allowed = [];
  if (mutations.includes('secret')) allowed.push(secretArgv(SLUG, secretName));
  if (mutations.includes('ruleset')) allowed.push(rulesetArgv(SLUG));
  const checks = allowed.length > 0 ? allowed.map((mutation) => assertApplyArgv({ slug: SLUG, branch: BRANCH, mutation })) : [assertApplyArgv({ slug: SLUG, branch: BRANCH, mutation: null })];
  const calls = [];
  const unexpected = [];
  const fake = {
    world,
    calls,
    unexpected,
    async exec(argv, { stdin = null, env = {} } = {}) {
      calls.push({ argv: [...argv], stdin: stdin === null ? null : Buffer.from(stdin), env: { ...env } });
      if (!checks.some((check) => { try { check(argv); return true; } catch { return false; } })) {
        unexpected.push(argv.join(' '));
        return httpError(400, 'unexpected call in test');
      }
      if (argv[0] === 'secret') {
        if (world.overrides['secret set']) return respond(world.overrides['secret set']);
        world.clock += 1;
        const at = `2026-10-03T00:00:${String(world.clock).padStart(2, '0')}Z`;
        const existing = world.secrets.find((s) => s.name === argv[2]);
        if (existing) existing.updated_at = at;
        else world.secrets.push({ name: argv[2], created_at: at, updated_at: at });
        return { stdout: '', stderr: '', exitCode: 0, error: null, timedOut: false, overflow: false };
      }
      if (argv[0] === 'api' && argv[2] === 'POST') {
        if (world.overrides['POST rulesets']) return respond(world.overrides['POST rulesets']);
        const body = JSON.parse(stdin.toString('utf8'));
        world.nextId += 1;
        const created = { id: world.nextId, source_type: 'Repository', source: SLUG, current_user_can_bypass: 'never', updated_at: '2026-10-03T00:00:00Z', ...body };
        world.rulesets.push(created);
        return ok(created);
      }
      const endpoint = argv[7];
      if (world.overrides[endpoint]) return respond(world.overrides[endpoint]);
      return route(world, endpoint);
    },
    mutationCalls: () => calls.filter((c) => c.argv[0] === 'secret' || (c.argv[0] === 'api' && c.argv[2] !== 'GET')),
    endpoints: () => calls.map((c) => (c.argv[0] === 'api' ? `${c.argv[2]} ${c.argv[7]}` : c.argv.slice(0, 3).join(' ')))
  };
  return fake;
}

// The repository facts `inspectRepository` would report for a clean clone.
export function facts({ slug = SLUG, defaultBranch = BRANCH, codeowners = '.github/CODEOWNERS', codeownersText = COMPLETE_CODEOWNERS, isGit = true } = {}) {
  return { git: { isGit, slug, defaultBranch, host: slug ? 'github.com' : null }, codeowners, codeownersText: codeowners ? codeownersText : null };
}
