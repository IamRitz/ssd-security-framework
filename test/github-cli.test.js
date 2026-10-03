// The GitHub CLI wrapper (onboarding/github/gh-cli.mjs): the read allowlist,
// endpoint construction, the two single-use mutators, the child environment,
// error classification and redaction — plus a real child process (a stand-in
// `gh` on PATH) proving argv, environment and stdin at the OS boundary.
import assert from 'node:assert/strict';
import { chmodSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';

import {
  GhCliError,
  assertRead,
  classifyFailure,
  execGh,
  ghEnv,
  readArgv,
  readEndpoints,
  readGh,
  redact,
  rulesetArgv,
  rulesetCreator,
  secretArgv,
  secretSetter
} from '../onboarding/github/gh-cli.mjs';
import { GitHubDataError, discoverActionsApp, discoverBranchRules, discoverClassic, discoverCodeowners, discoverRepository, discoverRulesetDetail, discoverRulesetList, discoverSecret } from '../onboarding/github/discover.mjs';
import { tempDir } from './support/onboarding-fixtures.mjs';
import { fixture, httpError } from './support/github-fake.mjs';

const SLUG = 'acme/app';
const BRANCH = 'main';
const WEBHOOK = Buffer.from('https://hooks.slack.com/services/T000/B000/abcdefghijklmnop');
const refused = (fn) => assert.throws(fn, (e) => e instanceof GhCliError && e.kind === 'refused');

describe('github wrapper: the read allowlist', () => {
  const check = assertRead(SLUG, BRANCH);
  const e = readEndpoints(SLUG, BRANCH);

  it('accepts exactly the GET argv of every builder-produced endpoint', () => {
    for (const endpoint of [e.user(), e.actionsApp(), e.repository(), e.secrets(1), e.branchRules(2), e.rulesets(10), e.ruleset(42), e.branch(), e.protection(), e.contents('.github/CODEOWNERS'), e.contents('CODEOWNERS'), e.contents('docs/CODEOWNERS'), e.codeownersErrors()]) {
      check(readArgv(endpoint));
    }
  });

  for (const [what, argv] of [
    ['another repository', readArgv('repos/evil/app')],
    ['a path escape', readArgv('repos/acme/app/../../evil/app')],
    ['another branch', readArgv('repos/acme/app/branches/release')],
    ['graphql', readArgv('graphql')],
    ['an arbitrary repository path', readArgv('repos/acme/app/actions/secrets/public-key')],
    ['an arbitrary contents path', readArgv('repos/acme/app/contents/.env?ref=main')],
    ['a page beyond the cap', readArgv('repos/acme/app/rulesets?includes_parents=true&per_page=100&page=11')],
    ['a POST', ['api', '--method', 'POST', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', 'repos/acme/app/rulesets']],
    ['a PUT of a ruleset', ['api', '--method', 'PUT', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', 'repos/acme/app/rulesets/42?includes_parents=true']],
    ['an extra -f field', [...readArgv('repos/acme/app'), '-f', 'x=y']],
    ['--input', [...readArgv('repos/acme/app').slice(0, -1), '--input', '-', 'repos/acme/app']],
    ['--paginate', ['api', '--paginate', ...readArgv('repos/acme/app').slice(1)]],
    ['--hostname', ['api', '--hostname', 'evil.example', ...readArgv('repos/acme/app').slice(1)]],
    ['secret set', secretArgv(SLUG, 'X')],
    ['a non-array', 'api repos/acme/app']
  ]) {
    it(`refuses ${what}`, () => refused(() => check(argv)));
  }

  it('builders refuse unvalidated identifiers and non-CODEOWNERS paths', () => {
    refused(() => readEndpoints('acme/app/../x', BRANCH));
    refused(() => readEndpoints(SLUG, 'main;rm -rf'));
    refused(() => readEndpoints(SLUG, '../main'));
    refused(() => e.contents('.env'));
    refused(() => e.ruleset(-1));
    refused(() => e.ruleset('42'));
    refused(() => e.secrets(0));
  });

  it('readGh.get takes an endpoint NAME, never a path', async () => {
    const calls = [];
    const gh = readGh({ slug: SLUG, branch: BRANCH, exec: async (argv) => (calls.push(argv), { stdout: '{}', stderr: '', exitCode: 0 }) });
    await assert.rejects(gh.get('repos/evil/app'), (err) => err.kind === 'refused');
    await gh.get('repository');
    assert.deepEqual(calls, [readArgv('repos/acme/app')]);
  });
});

describe('github wrapper: single-use mutators', () => {
  it('secret set: fixed argv, the value only on stdin, at most once', async () => {
    const calls = [];
    const setter = secretSetter({ slug: SLUG, name: 'SECURITY_NOTIFY_SLACK_URL', exec: async (argv, opts) => (calls.push({ argv, opts }), { stdout: '', stderr: '', exitCode: 0 }) });
    await setter.set(Buffer.from(WEBHOOK));
    assert.deepEqual(calls[0].argv, ['secret', 'set', 'SECURITY_NOTIFY_SLACK_URL', '--repo', 'github.com/acme/app', '--app', 'actions']);
    assert.ok(!calls[0].argv.join(' ').includes('hooks.slack'), 'not in argv');
    assert.ok(!calls[0].argv.includes('--body') && !calls[0].argv.includes('-b'));
    assert.deepEqual(calls[0].opts.stdin, WEBHOOK);
    assert.ok(!JSON.stringify(calls[0].opts.env ?? {}).includes('hooks.slack'), 'not in env');
    await assert.rejects(setter.set(Buffer.from(WEBHOOK)), (e) => e.kind === 'refused');
    assert.equal(calls.length, 1);
  });

  it('secret set refuses an invalid name or a missing value', async () => {
    refused(() => secretSetter({ slug: SLUG, name: 'GITHUB_TOKEN' }));
    refused(() => secretSetter({ slug: SLUG, name: 'lower' }));
    await assert.rejects(secretSetter({ slug: SLUG, name: 'X', exec: async () => ({}) }).set('string value'), (e) => e.kind === 'refused');
  });

  it('a gh error on secret set never echoes the value', async () => {
    const setter = secretSetter({
      slug: SLUG,
      name: 'X',
      exec: async (_argv, { stdin }) => ({ stdout: JSON.stringify({ message: `bad ${stdin.toString()}`, status: '422' }), stderr: `gh: bad ${stdin.toString()} (HTTP 422)`, exitCode: 1 })
    });
    await assert.rejects(setter.set(Buffer.from(WEBHOOK)), (e) => !e.message.includes(WEBHOOK.toString()) && !e.message.includes('hooks.slack') && e.message.includes('[REDACTED]'));
  });

  it('ruleset create: POST of the fixed body on stdin, at most once; no PUT/PATCH/DELETE exists', async () => {
    const calls = [];
    const body = JSON.stringify({ name: 'ssd-merge-governance' });
    const creator = rulesetCreator({ slug: SLUG, body, exec: async (argv, opts) => (calls.push({ argv, opts }), { stdout: '{"id":1}', stderr: '', exitCode: 0 }) });
    await creator.create();
    assert.deepEqual(calls[0].argv, rulesetArgv(SLUG));
    assert.equal(calls[0].opts.stdin.toString(), body);
    await assert.rejects(creator.create(), (e) => e.kind === 'refused');
    refused(() => rulesetCreator({ slug: SLUG, body: null }));
    const source = readFileSync('onboarding/github/gh-cli.mjs', 'utf8');
    assert.doesNotMatch(source, /'(?:PUT|PATCH|DELETE)'/);
  });
});

describe('github wrapper: environment, classification, redaction', () => {
  it('pins github.com and disables pagers, prompts, colour and debug logging', () => {
    const env = ghEnv({ PATH: '/bin', GH_TOKEN: 'x', GH_DEBUG: 'api', DEBUG: '1', GH_HOST: 'evil.example', GH_REPO: 'evil/app', PAGER: 'less', GH_ENTERPRISE_TOKEN: 'e' });
    assert.equal(env.GH_HOST, 'github.com');
    assert.equal(env.GH_PROMPT_DISABLED, '1');
    assert.equal(env.GH_PAGER, 'cat');
    assert.equal(env.NO_COLOR, '1');
    for (const gone of ['GH_DEBUG', 'DEBUG', 'GH_REPO', 'PAGER', 'GH_ENTERPRISE_TOKEN']) assert.equal(env[gone], undefined, gone);
    assert.equal(env.GH_TOKEN, 'x', "gh's own credential passes through");
  });

  it('classifies 401 / 403 / 404 / timeout / missing gh', () => {
    assert.equal(classifyFailure(httpError(401, 'Bad credentials')).kind, 'authentication');
    assert.equal(classifyFailure({ stderr: 'To get started with GitHub CLI, please run:  gh auth login' }).kind, 'authentication');
    assert.equal(classifyFailure(httpError(403, 'Resource not accessible by integration')).kind, 'authorization');
    const notFound = classifyFailure(httpError(404, 'Branch not protected'));
    assert.equal(notFound.kind, 'not-found');
    assert.equal(notFound.status, 404);
    assert.equal(classifyFailure({ timedOut: true }).kind, 'timeout');
    assert.equal(classifyFailure({ error: { code: 'ENOENT' } }).kind, 'command-unavailable');
    assert.equal(classifyFailure({ overflow: true }).kind, 'output-too-large');
  });

  it('authentication errors carry none of gh\'s text', () => {
    const e = classifyFailure({ stdout: '{"message":"Bad credentials ghp_abcdefghijklmnopqrstuvwxyz0123","status":"401"}', stderr: 'gh: Bad credentials (HTTP 401)' });
    assert.doesNotMatch(e.message, /ghp_/);
  });

  it('redacts tokens, credential env values, webhook URLs and supplied secrets', () => {
    const out = redact('a ghp_abcdefghijklmnopqrstuvwxyz0123 b github_pat_abcdefghijklmnopqrstuv c https://hooks.slack.com/services/T/B/x d sekret-value e TOKENVALUE123', {
      env: { GH_TOKEN: 'TOKENVALUE123' },
      secrets: [Buffer.from('sekret-value')]
    });
    assert.doesNotMatch(out, /ghp_|github_pat_|hooks\.slack|sekret-value|TOKENVALUE123/);
  });

  it('malformed or truncated JSON fails closed', async () => {
    for (const raw of ['', '{"full_name": "acme/app", "id": 4', 'not json', 'null']) {
      const gh = readGh({ slug: SLUG, branch: BRANCH, exec: async () => ({ stdout: raw, stderr: '', exitCode: 0 }) });
      await assert.rejects(gh.get('repository'), (e) => e.kind === 'malformed-json');
    }
  });

  it('the run-wide deadline ends the run', async () => {
    let t = 0;
    const gh = readGh({ slug: SLUG, branch: BRANCH, deadlineMs: 10, now: () => t, exec: async () => ((t += 20), { stdout: '{}', stderr: '', exitCode: 0 }) });
    await gh.get('repository');
    await assert.rejects(gh.get('repository'), (e) => e.kind === 'deadline');
  });
});

describe('github wrapper: a real child process', () => {
  // A stand-in `gh` that records what it received, then answers.
  function fakeGh(t, script) {
    const dir = tempDir(t, 'ssd-fake-gh-');
    const log = join(dir, 'log.json');
    writeFileSync(
      join(dir, 'gh'),
      `#!/usr/bin/env node
const fs = require('node:fs');
let stdin = '';
try { stdin = fs.readFileSync(0, 'utf8'); } catch {}
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ argv: process.argv.slice(2), stdin, env: process.env }));
${script}
`
    );
    chmodSync(join(dir, 'gh'), 0o755);
    return { env: { PATH: `${dir}:${process.env.PATH}`, GH_DEBUG: 'api' }, read: () => JSON.parse(readFileSync(log, 'utf8')) };
  }

  it('the secret reaches gh on stdin only — not argv, not the environment', async (t) => {
    const gh = fakeGh(t, '');
    await secretSetter({ slug: SLUG, name: 'SECURITY_NOTIFY_SLACK_URL', env: gh.env }).set(Buffer.from(WEBHOOK));
    const seen = gh.read();
    assert.equal(seen.stdin, WEBHOOK.toString());
    assert.ok(!seen.argv.join('\0').includes('hooks.slack'), 'argv');
    assert.ok(!Object.values(seen.env).join('\0').includes('hooks.slack'), 'environment');
    assert.equal(seen.env.GH_HOST, 'github.com');
    assert.equal(seen.env.GH_DEBUG, undefined, 'debug logging disabled');
  });

  it('a read sends an empty stdin, so gh can never wait on a terminal', async (t) => {
    const gh = fakeGh(t, 'process.stdout.write("{\\"ok\\":true}")');
    const out = await readGh({ slug: SLUG, branch: BRANCH, env: gh.env }).get('repository');
    assert.deepEqual(out, { ok: true });
    assert.equal(gh.read().stdin, '');
  });

  it('a hung gh is killed at the timeout and fails closed', async (t) => {
    const gh = fakeGh(t, 'setTimeout(() => {}, 60000)');
    const result = await execGh(['api', 'user'], { env: gh.env, timeoutMs: 300 });
    assert.equal(result.timedOut, true);
    await assert.rejects(readGh({ slug: SLUG, branch: BRANCH, env: gh.env, timeoutMs: 300 }).get('user'), (e) => e.kind === 'timeout');
  });

  it('no gh on PATH is command-unavailable', async () => {
    await assert.rejects(readGh({ slug: SLUG, branch: BRANCH, env: { PATH: '/nonexistent' } }).get('user'), (e) => e.kind === 'command-unavailable');
  });
});

describe('github trust boundary', () => {
  const read = (path) => readFileSync(path, 'utf8');
  const importsOf = (path) => [...read(path).matchAll(/^\s*(?:import|export)\s[^;]*?from\s+'([^']+)';/gms)].map((m) => m[1]);
  const files = readdirSync('onboarding/github').filter((n) => n.endsWith('.mjs')).map((n) => join('onboarding', 'github', n));
  const graph = (start) => {
    const seen = new Set();
    const visit = (path) => {
      if (seen.has(path)) return;
      seen.add(path);
      importsOf(path).filter((s) => s.startsWith('.')).forEach((s) => visit(join(dirname(path), s)));
    };
    visit(start);
    return seen;
  };

  it('no repository command can reach the GitHub mutators: cli.mjs reaches onboarding/github only by one dynamic import', () => {
    assert.deepEqual([...graph('onboarding/cli.mjs')].filter((p) => p.startsWith(join('onboarding', 'github'))), []);
    assert.equal((read('onboarding/cli.mjs').match(/import\('\.\/github\/cli\.mjs'\)/g) ?? []).length, 1);
  });

  it('only gh-cli.mjs runs a process; only record.mjs writes; GitHub and AWS never import each other', () => {
    for (const file of files) {
      const imports = importsOf(file);
      if (!file.endsWith('gh-cli.mjs')) assert.ok(!imports.includes('node:child_process'), `${file} runs a process`);
      if (!file.endsWith('record.mjs')) {
        for (const s of ['node:fs', 'node:fs/promises', '../lib/safe-path.mjs', '../lib/files.mjs']) assert.ok(!imports.includes(s), `${file} imports ${s}`);
      }
      assert.ok(!imports.some((s) => s.includes('/aws/')), `${file} imports AWS code`);
      assert.doesNotMatch(read(file), /spawn\(\s*'aws'|execFile\(\s*'aws'/, `${file} runs aws`);
    }
    for (const file of readdirSync('onboarding/aws', { recursive: true }).filter((n) => n.endsWith('.mjs'))) {
      assert.ok(!importsOf(join('onboarding', 'aws', file)).some((s) => s.includes('github/')), `aws/${file} imports GitHub code`);
    }
    assert.doesNotMatch(read('onboarding/github/record.mjs'), /\b(?:rm|unlink|rename|safeRemove|writeFile)\s*\(/, 'the record never removes, renames or truncating-writes');
    assert.match(read('onboarding/github/gh-cli.mjs'), /spawn\('gh', argv, \{ shell: false/);
  });

  it('only apply.mjs can reach a mutator; plan never names one', () => {
    for (const file of files.filter((f) => !/(apply|gh-cli)\.mjs$/.test(f))) {
      assert.doesNotMatch(read(file), /secretSetter|rulesetCreator/, `${file} names a mutator`);
    }
  });
});

describe('github discovery over the recorded fixtures', () => {
  // gh's observed behaviour: 2xx -> JSON on stdout; error -> the body on stdout
  // and `gh: <message> (HTTP <n>)` on stderr.
  const gh = (routes) =>
    readGh({
      slug: SLUG,
      branch: BRANCH,
      exec: async (argv) => {
        const route = routes[argv[7]];
        if (!route) return { stdout: '{"message":"Not Found","status":"404"}', stderr: 'gh: Not Found (HTTP 404)', exitCode: 1 };
        if (route.error) return { stdout: JSON.stringify(route.error), stderr: `gh: ${route.error.message} (HTTP ${route.error.status})`, exitCode: 1 };
        return { stdout: JSON.stringify(route), stderr: '', exitCode: 0 };
      }
    });
  const e = readEndpoints(SLUG, BRANCH);

  it('live shapes: repository, Actions app, empty rules/rulesets/secrets, unprotected branch', async () => {
    const g = gh({
      [e.repository()]: { ...fixture('live-repository.json'), full_name: SLUG },
      [e.actionsApp()]: fixture('live-actions-app.json'),
      [e.branchRules(1)]: fixture('live-rules-branch-empty.json'),
      [e.rulesets(1)]: fixture('live-rulesets-empty.json'),
      [e.secrets(1)]: fixture('live-secrets-empty.json'),
      [e.branch()]: fixture('live-branch-unprotected.json'),
      [e.protection()]: { error: fixture('live-protection-not-protected.json') }
    });
    const repo = await discoverRepository(g);
    assert.equal(repo.state, 'present');
    assert.equal(repo.value.permissions.admin, true);
    assert.deepEqual(await discoverActionsApp(g), { state: 'verified', id: 15368 });
    assert.deepEqual(await discoverBranchRules(g), { state: 'present', value: [] });
    assert.deepEqual(await discoverRulesetList(g), { state: 'present', value: [] });
    assert.equal((await discoverSecret(g, 'SECURITY_NOTIFY_SLACK_URL')).state, 'absent');
    assert.deepEqual(await discoverClassic(g), { state: 'absent' });
  });

  it('live 404 bodies: gh\'s string status is read, and absence is proven only where the token can read', async () => {
    const notProtected = classifyFailure({ stdout: JSON.stringify(fixture('live-protection-not-protected.json')), stderr: '' });
    assert.equal(notProtected.kind, 'not-found');
    assert.equal(notProtected.status, 404);
    const g = gh({ [e.codeownersErrors()]: { error: fixture('live-codeowners-errors-no-file.json') } });
    assert.deepEqual(await discoverCodeowners(g, { canRead: true }), { state: 'absent' });
    assert.equal((await discoverCodeowners(g, { canRead: false })).state, 'unverified');
  });

  it('documented shapes: rules for a branch, ruleset detail, classic protection, CODEOWNERS and its errors, secret metadata', async () => {
    const g = gh({
      [e.branchRules(1)]: fixture('doc-rules-branch.json'),
      [e.ruleset(42)]: fixture('doc-ruleset-detail.json'),
      [e.branch()]: { ...fixture('live-branch-unprotected.json'), protected: true },
      [e.protection()]: fixture('doc-protection.json'),
      [e.contents('.github/CODEOWNERS')]: fixture('doc-contents-codeowners.json'),
      [e.codeownersErrors()]: fixture('doc-codeowners-errors.json'),
      [e.secrets(1)]: fixture('doc-secrets-present.json')
    });
    const rules = await discoverBranchRules(g);
    assert.equal(rules.value.length, 3);
    const detail = await discoverRulesetDetail(g, 42);
    assert.deepEqual(detail.bypass_actors, []);
    assert.equal(detail.current_user_can_bypass, 'never');
    const classic = await discoverClassic(g);
    assert.equal(classic.state, 'present');
    assert.equal(classic.value.enforce_admins.enabled, true);
    assert.deepEqual(classic.value.required_status_checks.checks, [{ context: 'security-gate', app_id: 15368 }]);
    const co = await discoverCodeowners(g, { canRead: true });
    assert.equal(co.file.path, '.github/CODEOWNERS');
    assert.match(co.file.text, /^\/\.ssd\/ @acme\/security$/m);
    assert.equal(co.errors.list[0].kind, 'Unknown owner');
    const secret = await discoverSecret(g, 'SECURITY_NOTIFY_SLACK_URL');
    assert.deepEqual(secret, { state: 'present', metadata: { name: 'SECURITY_NOTIFY_SLACK_URL', createdAt: '2026-01-02T03:04:05Z', updatedAt: '2026-02-03T04:05:06Z' } });
    assert.ok(!('value' in secret.metadata), 'no value field exists');
  });

  it('a ruleset detail without bypass_actors keeps it ABSENT (unknown), never []', async () => {
    const { bypass_actors, current_user_can_bypass, ...hidden } = fixture('doc-ruleset-detail.json');
    const detail = await discoverRulesetDetail(gh({ [e.ruleset(42)]: hidden }), 42);
    assert.equal('bypass_actors' in detail, false);
  });

  it('CODEOWNERS content that does not match its size (truncated) fails closed', async () => {
    const doc = { ...fixture('doc-contents-codeowners.json'), size: 9999 };
    await assert.rejects(discoverCodeowners(gh({ [e.contents('.github/CODEOWNERS')]: doc }), { canRead: true }), (err) => err instanceof GitHubDataError);
  });
});
