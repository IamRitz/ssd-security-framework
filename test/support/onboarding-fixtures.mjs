// Shared fixtures for the ssd-onboard tests: raw configs per profile (as they
// would be parsed from .ssd/onboarding.yml) and throwaway git repositories.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { buildProvenance } from '../../security/scripts/baseline-provenance.mjs';
import { validateConfig } from '../../onboarding/lib/config.mjs';

export const REF = '068303774554f189b7444a0d3c95c6aeb7798608';
export const ACCOUNT = '012345678901';
export const PUSH_ROLE = `arn:aws:iam::${ACCOUNT}:role/app-ecr-push-scan`;
export const DEPLOY_ROLE = `arn:aws:iam::${ACCOUNT}:role/app-deploy`;

export function rawConfig(profile = 'source-only', overrides = {}) {
  const base = {
    schemaVersion: '1',
    repository: { slug: 'acme/app', defaultBranch: 'main' },
    framework: { repository: 'IamRitz/ssd-security-framework', ref: REF },
    profile,
    workflows: { security: '.github/workflows/security.yml' },
    rollout: { gateMode: 'log-only' },
    semgrep: {
      rulesets: ['p/owasp-top-ten', 'p/python'],
      roots: ['.'],
      ignore: { managed: true, patterns: [] },
      baseline: { path: 'security/baseline/semgrep-baseline.json', state: 'absent' }
    },
    gitleaks: { mode: 'default' },
    trufflehog: { excludePathsFile: '' },
    notifications: { slack: { enabled: false, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } },
    breakGlass: { mode: 'disabled' }
  };
  if (profile !== 'source-only') {
    base.container = { dockerfile: 'Dockerfile', context: '.', imageName: 'app' };
  }
  if (profile === 'container-ecr-framework-gated') {
    base.workflows.delivery = '.github/workflows/deploy.yml';
    base.delivery = {
      aws: { accountId: ACCOUNT, region: 'us-east-1' },
      ecr: { repository: 'app', ownership: 'existing' },
      oidcProvider: 'existing',
      roles: { pushScanRoleArn: PUSH_ROLE, pushScanOwnership: 'existing', deployRoleArn: DEPLOY_ROLE, deployOwnership: 'existing' },
      ssm: { instanceId: 'i-0123456789abcdef0', appPort: '8080', containerName: 'app' }
    };
  }
  return deepMerge(base, overrides);
}

export function deepMerge(base, override) {
  if (Array.isArray(override) || override === null || typeof override !== 'object') {
    return override === undefined ? base : override;
  }
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = value === undefined ? undefined : deepMerge(base?.[key], value);
    if (out[key] === undefined) {
      delete out[key];
    }
  }
  return out;
}

// A valid, normalized config. Throws when the fixture itself is invalid.
export function config(profile, overrides) {
  const { config: normalized, errors } = validateConfig(rawConfig(profile, overrides));
  if (errors.length > 0) {
    throw new Error(`fixture config invalid: ${JSON.stringify(errors)}`);
  }
  return normalized;
}

const git = (cwd, ...args) => execFileSync('git', ['-C', cwd, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();

export const TEMP_PREFIX = 'ssd-onboard-';

// Every temporary directory this module creates is OWNED by the test that asked
// for it: the caller passes the node:test context `t` (or any `{ after(fn) }`
// registrar) and removal is registered before the directory is populated. So the
// root is removed when the test passes, when an assertion fails, and when the
// fixture itself throws half-built — without any process-exit hook and without
// ever touching a directory this module did not create.
export function tempDir(t, prefix = TEMP_PREFIX) {
  if (typeof t?.after !== 'function') {
    throw new TypeError(`${prefix}: pass the test context (t) so the temporary directory is cleaned up`);
  }
  const root = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

// A git repository whose origin is github.com/acme/app with default branch
// `main`, containing `files` (path -> content), committed. Cleaned up when the
// owning test (`t`) finishes.
export function makeRepo(t, files = {}) {
  const root = tempDir(t);
  try {
    return buildRepo(root, files);
  } catch (error) {
    // The root exists but is half-built: remove it now rather than leaving it
    // to the registered hook, which may never run if setup failed this early.
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

function buildRepo(root, files) {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  git(root, 'init', '-q', '-b', 'main');
  git(root, 'config', 'user.email', 'test@example.invalid');
  git(root, 'config', 'user.name', 'test');
  git(root, 'config', 'commit.gpgsign', 'false');
  git(root, 'remote', 'add', 'origin', 'https://github.com/acme/app.git');
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '--allow-empty', '-m', 'fixture');
  git(root, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
  git(root, 'symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  return root;
}

export const read = (root, path) => readFileSync(join(root, path), 'utf8');
export const write = (root, path, content) => {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), content);
};

// The framework's own reusable workflows (this working tree) stand in for the
// pinned ref in contract checks.
export const readWorkingTreeWorkflow = async (file) => {
  try {
    return readFileSync(join('.github/workflows', file), 'utf8');
  } catch {
    return null;
  }
};

// A framework identity BOUND to REF: what detectFramework() returns when the
// CLI runs from a clean checkout at REF. The working-tree reusable workflows
// stand in for the contracts at REF.
export const FRAMEWORK = Object.freeze({
  root: '.',
  sha: REF,
  clean: true,
  dirtyPaths: [],
  slug: 'IamRitz/ssd-security-framework',
  readWorkflow: readWorkingTreeWorkflow
});

export const head = (root) => git(root, 'rev-parse', 'HEAD').trim();
export const commitAll = (root, message = 'change') => {
  git(root, 'add', '-A');
  git(root, 'commit', '-q', '--allow-empty', '-m', message);
};

// A `security-gate-results` artifact exactly as the bootstrap run writes it,
// with provenance produced by the real toolkit script for (root, config).
export function bootstrapArtifact(root, cfg, { env = {}, candidate = SAMPLE_BASELINE, gate = null, semgrepignore } = {}) {
  const candidateBytes = Buffer.from(JSON.stringify(candidate, null, 2));
  const gateResult = gate ?? {
    verdict: 'BLOCK',
    integrity: { trusted: true, failures: [] },
    bootstrap: { active: true, reason: 'fixture' },
    scannerExecution: { records: [{ scanner: 'semgrep', image: 'semgrep/semgrep@sha256:' + 'e'.repeat(64) }] }
  };
  let ignoreBytes = null;
  try {
    ignoreBytes = semgrepignore === undefined ? readFileSync(join(root, '.semgrepignore')) : semgrepignore === null ? null : Buffer.from(semgrepignore);
  } catch {
    ignoreBytes = null;
  }
  const provenance = buildProvenance({
    env: {
      CI_REPOSITORY: cfg.repository.slug,
      CI_REPOSITORY_ID: '4242424',
      CI_DEFAULT_BRANCH: cfg.repository.defaultBranch,
      CI_SHA: head(root),
      CI_REF: `refs/heads/${cfg.repository.defaultBranch}`,
      CI_EVENT: 'workflow_dispatch',
      CI_RUN_ID: '4242',
      CI_RUN_ATTEMPT: '1',
      TOOLKIT_REPOSITORY: cfg.framework.repository,
      TOOLKIT_REF: cfg.framework.ref,
      SEMGREP_CONFIGS: cfg.semgrep.rulesets.join('\n'),
      SEMGREP_PATHS: cfg.semgrep.roots.join(' '),
      BASELINE_PATH: cfg.semgrep.baseline.path,
      ...env
    },
    candidateBytes,
    gate: gateResult,
    semgrepignoreBytes: ignoreBytes
  });
  return {
    'security-gate.json': JSON.stringify(gateResult),
    'semgrep-baseline.candidate.json': candidateBytes.toString('utf8'),
    'semgrep-baseline.candidate.provenance.json': JSON.stringify(provenance, null, 2),
    provenance
  };
}

// Output capture for cli main().
export function capture() {
  const out = [];
  const err = [];
  return {
    out,
    err,
    io: { out: (text) => out.push(text), err: (text) => err.push(text) },
    text: () => out.join('\n'),
    errors: () => err.join('\n')
  };
}

export const SAMPLE_BASELINE = {
  schemaVersion: 1,
  generatedBy: 'semgrep 1.176.0',
  rulesets: ['p/owasp-top-ten', 'p/python'],
  findings: [
    { fingerprint: 'a'.repeat(64), checkId: 'python.lang.security.audit.eval-detected', path: 'src/app.py' },
    { fingerprint: 'b'.repeat(64), checkId: 'python.lang.security.audit.eval-detected', path: 'tests/test_app.py' }
  ]
};
