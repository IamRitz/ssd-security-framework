// The ONE way `ssd-onboard github …` runs the GitHub CLI.
//
// TRUST BOUNDARY. Three factories, no generic wrapper:
//
//   readGh({ slug, branch })   `github plan` and the re-checks of `github
//                              apply`. GET only: every call is a fixed argv
//                              `api --method GET -H <accept> -H <version>
//                              <endpoint>`, and the endpoint must be one the
//                              builders below produce for THIS repository and
//                              THIS default branch. Callers name an endpoint;
//                              they never pass a path.
//   secretSetter({ slug, name })
//                              `github apply` of a secrets plan. Its single
//                              mutation is `secret set <NAME> --repo
//                              github.com/<o>/<r> --app actions` with the value
//                              written to the child's STDIN, at most once.
//                              The value is never in argv or the environment.
//   rulesetCreator({ slug, body })
//                              `github apply` of a protection plan. Its single
//                              mutation is `api --method POST
//                              repos/<o>/<r>/rulesets --input -` with the
//                              plan's exact ruleset JSON on stdin, at most
//                              once. There is no PUT, PATCH or DELETE anywhere.
//
//   - every argv is checked against the allowlist BEFORE anything runs; the
//     fake GitHub in the tests checks every argv against it independently;
//   - endpoints are built only from the validated repository slug, a numeric
//     ruleset id and the validated default branch, never from repository
//     content or GitHub responses;
//   - spawn with an argv array and shell: false; the child's environment pins
//     GH_HOST=github.com and disables pagers, prompts, colour, the update
//     notifier and gh's debug logging (which could print request bodies);
//   - bounded output and a per-call timeout inside a run-wide deadline;
//   - authentication comes only from gh's own login or GH_TOKEN. Nothing here
//     reads, accepts or prints a token; error text is reduced to the HTTP
//     status and GitHub's message, with token-shaped values, the credential
//     environment values and any caller-supplied secret redacted.
import { spawn } from 'node:child_process';

export const GH_HOST = 'github.com';
export const API_VERSION = '2022-11-28';
const ACCEPT = 'Accept: application/vnd.github+json';
const VERSION = `X-GitHub-Api-Version: ${API_VERSION}`;

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_DEADLINE_MS = 180_000;
export const DEFAULT_MAX_BUFFER = 8 * 1024 * 1024;
// Pages of 100; a repository with more secrets or rulesets than this is
// reported NOT VERIFIED rather than judged on a partial list.
export const MAX_PAGES = 10;

// The same shapes the configuration schema enforces (lib/config.mjs).
export const SLUG = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/;
export const BRANCH = /^(?!-)(?!.*\.\.)(?!.*\/\/)(?!.*\/$)(?!.*\.lock$)[A-Za-z0-9._/-]{1,200}$/;
export const SECRET_NAME = /^(?!GITHUB_)[A-Z_][A-Z0-9_]{0,99}$/;
// GitHub's CODEOWNERS lookup order: the first file found is the one it uses.
export const CODEOWNERS_PATHS = Object.freeze(['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']);

// --- errors -----------------------------------------------------------------------

// kind:
//   refused              the allowlist rejected the argv; nothing was executed
//   command-unavailable  no `gh` executable
//   authentication       not logged in / bad token (HTTP 401)
//   authorization        HTTP 403
//   not-found            HTTP 404 (GitHub also answers 404 for "no access")
//   timeout / deadline   the call / the run's time budget ran out
//   output-too-large     more output than accepted
//   malformed-json       exit 0 without one JSON document
//   gh-error             anything else (HTTP status kept when known)
export class GhCliError extends Error {
  constructor(kind, message, { status = null, endpoint = null } = {}) {
    super(message);
    this.name = 'GhCliError';
    this.kind = kind;
    this.status = status;
    this.endpoint = endpoint;
  }
}

// Kinds that end a run: nothing after them can be trusted.
export const FATAL_KINDS = new Set(['refused', 'command-unavailable', 'authentication', 'timeout', 'deadline', 'output-too-large', 'malformed-json']);

const TOKEN_SHAPES = [
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /https:\/\/hooks\.slack(?:-gov)?\.com\/\S*/gi,
  /\bxox[abeoprs]-[A-Za-z0-9-]{8,}/g
];
const CREDENTIAL_ENV = ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'];
const MAX_MESSAGE = 300;

// Text safe to show or record: no token shape, no credential env value, no
// caller-supplied secret (Buffers or strings), bounded length.
export function redact(message, { env = process.env, secrets = [] } = {}) {
  let out = String(message ?? '');
  for (const secret of secrets) {
    const value = Buffer.isBuffer(secret) ? secret.toString('utf8') : String(secret ?? '');
    if (value.length >= 4) {
      out = out.split(value).join('[REDACTED]');
    }
  }
  for (const name of CREDENTIAL_ENV) {
    const value = env[name];
    if (typeof value === 'string' && value.length >= 8) {
      out = out.split(value).join('[REDACTED]');
    }
  }
  for (const shape of TOKEN_SHAPES) {
    out = out.replace(shape, '[REDACTED]');
  }
  out = out.trim();
  return out.length > MAX_MESSAGE ? `${out.slice(0, MAX_MESSAGE)}…` : out;
}

const HTTP_STATUS = /\(HTTP (\d{3})\)/;
const NOT_LOGGED_IN = [/gh auth login/i, /not logged in/i, /authentication required/i, /no oauth token/i, /Bad credentials/i];

// A failed execution -> GhCliError. gh prints the error body on stdout and
// `gh: <message> (HTTP <status>)` on stderr.
export function classifyFailure({ stdout = '', stderr = '', error = null, timedOut = false, overflow = false } = {}, { env = process.env, secrets = [], endpoint = null } = {}) {
  if (error?.code === 'ENOENT') {
    return new GhCliError('command-unavailable', 'the `gh` command was not found on PATH (install the GitHub CLI)', { endpoint });
  }
  if (overflow) {
    return new GhCliError('output-too-large', 'gh printed more output than ssd-onboard accepts', { endpoint });
  }
  if (timedOut) {
    return new GhCliError('timeout', 'gh did not finish before the timeout', { endpoint });
  }
  let body = null;
  try {
    body = JSON.parse(stdout);
  } catch {
    body = null;
  }
  const fromStderr = HTTP_STATUS.exec(String(stderr));
  const fromBody = body && typeof body === 'object' && /^\d{3}$/.test(String(body.status ?? '')) ? Number(body.status) : null;
  const status = fromStderr ? Number(fromStderr[1]) : fromBody;
  const githubMessage = body && typeof body === 'object' && typeof body.message === 'string' ? body.message : null;
  const message = redact(githubMessage ?? String(stderr).split('\n').find((line) => line.trim()) ?? 'gh failed without an error message', { env, secrets });
  if (status === 401 || (status === null && NOT_LOGGED_IN.some((p) => p.test(String(stderr))))) {
    // Deliberately WITHOUT gh's text: it can describe the credential source.
    return new GhCliError('authentication', 'GitHub authentication failed: gh is not logged in or its token is invalid (run `gh auth login`)', { status, endpoint });
  }
  if (status === 403) {
    return new GhCliError('authorization', message, { status, endpoint });
  }
  if (status === 404) {
    return new GhCliError('not-found', message, { status, endpoint });
  }
  return new GhCliError('gh-error', status ? `HTTP ${status}: ${message}` : message, { status, endpoint });
}

// --- endpoints --------------------------------------------------------------------

const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const PAGE = (page) => {
  if (!Number.isInteger(page) || page < 1 || page > MAX_PAGES) {
    throw new GhCliError('refused', `refusing page ${page}: pages run from 1 to ${MAX_PAGES}`);
  }
  return page;
};
const RULESET_ID = (id) => {
  if (!Number.isSafeInteger(id) || id < 1) {
    throw new GhCliError('refused', 'refusing a ruleset id that is not a positive integer');
  }
  return id;
};

function assertTarget(slug, branch) {
  if (typeof slug !== 'string' || !SLUG.test(slug)) {
    throw new GhCliError('refused', 'refusing to address a repository that is not a validated owner/name');
  }
  if (branch !== undefined && (typeof branch !== 'string' || !BRANCH.test(branch))) {
    throw new GhCliError('refused', 'refusing to address a branch that is not a validated branch name');
  }
}

// The read endpoints for one repository and its default branch, by name. The
// ONLY producer of read endpoint strings.
export function readEndpoints(slug, branch) {
  assertTarget(slug, branch);
  const repo = `repos/${slug}`;
  return Object.freeze({
    user: () => 'user',
    actionsApp: () => 'apps/github-actions',
    repository: () => repo,
    secrets: (page) => `${repo}/actions/secrets?per_page=100&page=${PAGE(page)}`,
    branchRules: (page) => `${repo}/rules/branches/${branch}?per_page=100&page=${PAGE(page)}`,
    rulesets: (page) => `${repo}/rulesets?includes_parents=true&per_page=100&page=${PAGE(page)}`,
    ruleset: (id) => `${repo}/rulesets/${RULESET_ID(id)}?includes_parents=true`,
    branch: () => `${repo}/branches/${branch}`,
    protection: () => `${repo}/branches/${branch}/protection`,
    contents: (path) => {
      if (!CODEOWNERS_PATHS.includes(path)) {
        throw new GhCliError('refused', 'refusing a contents path that is not a CODEOWNERS location');
      }
      return `${repo}/contents/${path}?ref=${branch}`;
    },
    codeownersErrors: () => `${repo}/codeowners/errors?ref=${branch}`
  });
}

// The same set as patterns, for the independent argv check.
function readPatterns(slug, branch) {
  const r = `repos/${escapeRe(slug)}`;
  const b = escapeRe(branch);
  const page = '(?:[1-9]|10)';
  return [
    '^user$',
    '^apps/github-actions$',
    `^${r}$`,
    `^${r}/actions/secrets\\?per_page=100&page=${page}$`,
    `^${r}/rules/branches/${b}\\?per_page=100&page=${page}$`,
    `^${r}/rulesets\\?includes_parents=true&per_page=100&page=${page}$`,
    `^${r}/rulesets/[1-9][0-9]{0,15}\\?includes_parents=true$`,
    `^${r}/branches/${b}$`,
    `^${r}/branches/${b}/protection$`,
    `^${r}/contents/(?:\\.github/CODEOWNERS|CODEOWNERS|docs/CODEOWNERS)\\?ref=${b}$`,
    `^${r}/codeowners/errors\\?ref=${b}$`
  ].map((p) => new RegExp(p));
}

export const readArgv = (endpoint) => ['api', '--method', 'GET', '-H', ACCEPT, '-H', VERSION, endpoint];
export const secretArgv = (slug, name) => ['secret', 'set', name, '--repo', `${GH_HOST}/${slug}`, '--app', 'actions'];
export const rulesetArgv = (slug) => ['api', '--method', 'POST', '-H', ACCEPT, '-H', VERSION, `repos/${slug}/rulesets`, '--input', '-'];

const sameArgv = (a, b) => Array.isArray(a) && a.length === b.length && a.every((v, i) => v === b[i]);

// Throws unless argv is exactly a GET of one of the repository's read
// endpoints. Checked before the executor is reached.
export function assertRead(slug, branch) {
  assertTarget(slug, branch);
  const patterns = readPatterns(slug, branch);
  return (argv) => {
    if (!Array.isArray(argv) || !argv.every((a) => typeof a === 'string')) {
      throw new GhCliError('refused', 'refusing a gh call that is not an argv array of strings');
    }
    const endpoint = argv[argv.length - 1];
    if (!sameArgv(argv, readArgv(endpoint)) || !patterns.some((p) => p.test(endpoint))) {
      throw new GhCliError('refused', `refusing 'gh ${argv.slice(0, 3).join(' ')}…': not a GET of an endpoint in the read-only allowlist (github plan makes no GitHub change)`);
    }
  };
}

// --- execution --------------------------------------------------------------------

// The child's environment: gh's own credentials, nothing that redirects,
// pages, prompts or logs. GH_TOKEN / GITHUB_TOKEN pass through (they ARE gh's
// credentials); they are never printed.
export function ghEnv(env = process.env) {
  const out = { ...env };
  for (const name of ['GH_DEBUG', 'DEBUG', 'GH_REPO', 'GH_HOST', 'GH_PAGER', 'PAGER', 'GH_BROWSER', 'BROWSER', 'GH_EDITOR', 'EDITOR', 'VISUAL', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN', 'HTTPS_PROXY_INSECURE']) {
    delete out[name];
  }
  return { ...out, GH_HOST, GH_PAGER: 'cat', GH_PROMPT_DISABLED: '1', GH_NO_UPDATE_NOTIFIER: '1', GH_SPINNER_DISABLED: '1', NO_COLOR: '1', CLICOLOR: '0' };
}

// The real executor: spawn, argv array, no shell; stdin is the given bytes or
// closed immediately (so gh can never wait on a terminal). Resolves with
// { stdout, stderr, exitCode, error, timedOut, overflow } and never rejects.
export function execGh(argv, { stdin = null, timeoutMs = DEFAULT_TIMEOUT_MS, maxBuffer = DEFAULT_MAX_BUFFER, env = process.env } = {}) {
  return new Promise((resolvePromise) => {
    let child;
    try {
      child = spawn('gh', argv, { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: ghEnv(env) });
    } catch (error) {
      resolvePromise({ stdout: '', stderr: '', exitCode: null, error, timedOut: false, overflow: false });
      return;
    }
    const out = [];
    const err = [];
    let size = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    const finish = (result) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolvePromise(result);
      }
    };
    const collect = (sink) => (chunk) => {
      size += chunk.length;
      if (size > maxBuffer) {
        overflow = true;
        child.kill('SIGTERM');
        return;
      }
      sink.push(chunk);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs);
    child.stdout.on('data', collect(out));
    child.stderr.on('data', collect(err));
    child.on('error', (error) => finish({ stdout: '', stderr: '', exitCode: null, error, timedOut, overflow }));
    child.on('close', (code) => {
      finish({ stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8'), exitCode: code, error: null, timedOut, overflow });
    });
    child.stdin.on('error', () => {}); // a child that exits early must not crash the CLI
    if (stdin !== null) {
      child.stdin.end(stdin);
    } else {
      child.stdin.end();
    }
  });
}

function runner({ exec = execGh, env = process.env, timeoutMs = DEFAULT_TIMEOUT_MS, deadlineMs = DEFAULT_DEADLINE_MS, now = Date.now, onCall = () => {} } = {}) {
  const startedAt = now();
  // secrets: values to redact from any error text (the stdin of a mutation).
  return async function run(argv, { stdin = null, allowEmpty = false, secrets = [] } = {}) {
    const endpoint = argv[0] === 'api' ? argv[7] : `${argv[0]} ${argv[1]}`;
    const remaining = deadlineMs - (now() - startedAt);
    if (remaining <= 0) {
      throw new GhCliError('deadline', `the run's overall GitHub time budget (${Math.round(deadlineMs / 1000)}s) is spent`, { endpoint });
    }
    const callTimeout = Math.min(timeoutMs, remaining);
    onCall([...argv]);
    const result = await exec([...argv], { stdin, timeoutMs: callTimeout, env });
    if (result.error || result.exitCode !== 0 || result.timedOut || result.overflow) {
      const failure = classifyFailure(result, { env, secrets, endpoint });
      throw failure.kind === 'timeout' && callTimeout < timeoutMs ? new GhCliError('deadline', 'the run\'s overall GitHub time budget is spent', { endpoint }) : failure;
    }
    if (allowEmpty && result.stdout.trim() === '') {
      return null;
    }
    try {
      const parsed = JSON.parse(result.stdout);
      if (parsed === null || typeof parsed !== 'object') {
        throw new Error('not a JSON document');
      }
      return parsed;
    } catch {
      throw new GhCliError('malformed-json', `GitHub did not return one complete JSON document for ${redact(endpoint, { env })}`, { endpoint });
    }
  };
}

// readGh({ slug, branch, ...options }) -> { get(name, ...args), endpoints }.
// get() resolves to the parsed JSON (object or array) or throws GhCliError.
export function readGh({ slug, branch, ...options } = {}) {
  const endpoints = readEndpoints(slug, branch);
  const check = assertRead(slug, branch);
  const run = runner(options);
  return Object.freeze({
    endpoints,
    async get(name, ...args) {
      if (!Object.hasOwn(endpoints, name)) {
        throw new GhCliError('refused', `refusing unknown read endpoint '${name}'`);
      }
      const argv = readArgv(endpoints[name](...args));
      check(argv);
      return run(argv);
    }
  });
}

// secretSetter({ slug, name, ...options }) -> { set(value: Buffer) } — once.
export function secretSetter({ slug, name, ...options } = {}) {
  assertTarget(slug);
  if (typeof name !== 'string' || !SECRET_NAME.test(name)) {
    throw new GhCliError('refused', 'refusing a secret name that is not a validated UPPER_SNAKE name');
  }
  const run = runner(options);
  let used = false;
  return Object.freeze({
    argv: secretArgv(slug, name),
    async set(value) {
      if (used) {
        throw new GhCliError('refused', 'refusing a second secret write: a plan is applied at most once');
      }
      if (!Buffer.isBuffer(value) || value.length === 0) {
        throw new GhCliError('refused', 'refusing to set a secret without a value');
      }
      used = true;
      return run(secretArgv(slug, name), { stdin: value, allowEmpty: true, secrets: [value] });
    }
  });
}

// rulesetCreator({ slug, body, ...options }) -> { create() } — once, with the
// body fixed at construction (the reviewed plan's document).
export function rulesetCreator({ slug, body, ...options } = {}) {
  assertTarget(slug);
  if (typeof body !== 'string' || !body.startsWith('{')) {
    throw new GhCliError('refused', 'refusing to create a ruleset without the plan\'s exact JSON document');
  }
  const run = runner(options);
  let used = false;
  return Object.freeze({
    argv: rulesetArgv(slug),
    async create() {
      if (used) {
        throw new GhCliError('refused', 'refusing a second ruleset creation: a plan is applied at most once');
      }
      used = true;
      return run(rulesetArgv(slug), { stdin: Buffer.from(body, 'utf8') });
    }
  });
}

// Every argv `github apply` may produce for one plan: its reads plus, exactly,
// its single mutation. Used by the test fake as an independent check.
export function assertApplyArgv({ slug, branch, mutation }) {
  const read = assertRead(slug, branch);
  return (argv) => {
    if (mutation && sameArgv(argv, mutation)) {
      return;
    }
    read(argv);
  };
}
