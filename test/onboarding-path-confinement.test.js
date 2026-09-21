// Filesystem confinement for every ssd-onboard write into a consumer
// repository (onboarding/lib/safe-path.mjs).
//
// The threat is a checkout that already contains symlinked path components when
// ssd-onboard runs: `security -> /tmp/elsewhere` turns a nominally relative,
// '..'-free, lexically-confined write into a write outside the repository.
// These tests therefore never assert on the string of a path; they assert that
// the OUTSIDE file was not created, not modified and not deleted.
//
// Every temporary directory here is created by the owning test through tempDir()
// and removed when that test finishes, so the suite is safe to run concurrently
// and makes no assumption about a shared /tmp layout.
import assert from 'node:assert/strict';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import {
  PathConfinementError,
  assertSafeRepoPath,
  safeMkdir,
  safeRemove,
  safeWriteFile
} from '../onboarding/lib/safe-path.mjs';
import { CANDIDATE_DIR, CANDIDATE_FILE } from '../onboarding/lib/baseline.mjs';
import { parseConfig, serializeConfig } from '../onboarding/lib/config.mjs';
import { applyWrites, planWrites, removeFile, withMarker } from '../onboarding/lib/files.mjs';
import {
  FRAMEWORK,
  bootstrapArtifact,
  capture,
  commitAll,
  config,
  head,
  makeRepo,
  read,
  tempDir,
  write
} from './support/onboarding-fixtures.mjs';

const PY_REPO = {
  'src/app.py': 'print("hi")\n',
  'tests/test_app.py': 'def test(): pass\n',
  'requirements.txt': 'requests==2.32.5\n'
};

// A sandbox owned by the test: { root } is the pretend consumer repository,
// { outside } is the directory an attacker's symlink points at.
function sandbox(t) {
  const base = tempDir(t, 'ssd-confine-');
  const root = join(base, 'repo');
  const outside = join(base, 'outside');
  mkdirSync(root, { recursive: true });
  mkdirSync(outside, { recursive: true });
  return { base, root, outside };
}

// Runs `fn`, asserts it threw a PathConfinementError, and returns the message.
async function refused(fn) {
  let caught = null;
  try {
    await fn();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, 'expected a refusal, but the operation succeeded');
  assert.ok(caught instanceof PathConfinementError, `wrong error: ${caught.message}`);
  assert.equal(caught.name, 'PathConfinementError');
  assert.equal(caught.code, 'ERR_PATH_NOT_CONFINED');
  return caught.message;
}

describe('safe-path: repository-relative paths', () => {
  it('a normal in-repo write succeeds and lands under the root', async (t) => {
    const { root } = sandbox(t);
    const target = await safeWriteFile(root, '.github/workflows/security.yml', 'name: ok\n');
    assert.equal(readFileSync(join(root, '.github/workflows/security.yml'), 'utf8'), 'name: ok\n');
    assert.ok(target.endsWith(join('repo', '.github', 'workflows', 'security.yml')));
  });

  it('missing parent directories are created, and stay confined', async (t) => {
    const { root } = sandbox(t);
    await safeWriteFile(root, 'a/b/c/d.json', '{}\n');
    assert.equal(readFileSync(join(root, 'a/b/c/d.json'), 'utf8'), '{}\n');
    await safeMkdir(root, 'x/y/z');
    assert.ok(existsSync(join(root, 'x/y/z')));
  });

  it('a lexical escape is refused', async (t) => {
    const { root, outside } = sandbox(t);
    const message = await refused(() => safeWriteFile(root, '../../outside/escaped.txt', 'x'));
    assert.equal(message, "refusing '../../outside/escaped.txt': the path escapes the repository root");
    assert.ok(!existsSync(join(outside, 'escaped.txt')));
    // Also rejected when the '..' is buried mid-path.
    assert.match(
      await refused(() => safeWriteFile(root, 'a/../../outside/escaped.txt', 'x')),
      /the path escapes the repository root$/
    );
    assert.deepEqual(readdirSync(outside), []);
  });

  it('an absolute path is refused', async (t) => {
    const { root, outside } = sandbox(t);
    const absolute = join(outside, 'absolute.txt');
    const message = await refused(() => safeWriteFile(root, absolute, 'x'));
    assert.equal(message, `refusing '${absolute}': an absolute path is not a repository-relative path`);
    assert.ok(!existsSync(absolute));
  });

  it('an empty path is refused', async (t) => {
    const { root } = sandbox(t);
    assert.match(await refused(() => safeWriteFile(root, '', 'x')), /a repository-relative path is required$/);
    assert.match(await refused(() => safeWriteFile(root, '.', 'x')), /a repository-relative path is required$/);
  });

  // A name that merely BEGINS with '..' is an ordinary name, not a traversal:
  // relative(root, root + '/..cache') is '..cache'. Rejecting it would refuse
  // legitimate in-repo paths (see within() in safe-path.mjs).
  it("a path component that starts with '..' but does not traverse is inside the root", async (t) => {
    const { root, outside } = sandbox(t);
    await safeWriteFile(root, '..cache/file.json', '{}\n');
    assert.equal(readFileSync(join(root, '..cache/file.json'), 'utf8'), '{}\n');

    await safeWriteFile(root, '..generated', 'x\n');
    assert.equal(readFileSync(join(root, '..generated'), 'utf8'), 'x\n');

    // Deeper, and with the odd name as a non-first component.
    await safeWriteFile(root, 'a/..b/...c/d.txt', 'y\n');
    assert.equal(readFileSync(join(root, 'a/..b/...c/d.txt'), 'utf8'), 'y\n');

    // The existing-ancestor walk agrees once these really exist on disk.
    assert.equal(await assertSafeRepoPath(root, '..cache/file.json'), join(root, '..cache/file.json'));
    assert.equal(await assertSafeRepoPath(root, '..generated'), join(root, '..generated'));

    await safeRemove(root, '..cache', { recursive: true });
    assert.ok(!existsSync(join(root, '..cache')));
    assert.deepEqual(readdirSync(outside), [], 'nothing was written outside the repository');
  });

  it("a real '..' traversal is still rejected alongside the '..'-prefixed names", async (t) => {
    const { root, outside } = sandbox(t);
    writeFileSync(join(outside, 'victim.txt'), 'keep\n');
    for (const path of ['../outside/victim.txt', '..', '../', 'a/../../outside/victim.txt', '..cache/../../outside/victim.txt']) {
      const message = await refused(() => safeWriteFile(root, path, 'attacker\n'));
      assert.match(message, /the path escapes the repository root$|a repository-relative path is required$/, path);
    }
    assert.equal(readFileSync(join(outside, 'victim.txt'), 'utf8'), 'keep\n');
    assert.deepEqual(readdirSync(outside), ['victim.txt']);
  });

  it('an unresolvable repository root is refused (fail closed)', async (t) => {
    const { base } = sandbox(t);
    assert.match(
      await refused(() => safeWriteFile(join(base, 'no-such-repo'), 'a.txt', 'x')),
      /the repository root .* could not be resolved/
    );
  });
});

describe('safe-path: symlinked path components', () => {
  it('a symlinked parent that escapes the root is refused, and nothing outside is created', async (t) => {
    const { root, outside } = sandbox(t);
    symlinkSync(outside, join(root, 'security'));
    const message = await refused(() => safeWriteFile(root, 'security/baseline/file.json', '{}'));
    assert.equal(
      message,
      "refusing 'security/baseline/file.json': 'security' is a symbolic link; ssd-onboard does not write through symbolic links"
    );
    assert.ok(!existsSync(join(outside, 'baseline')));
    assert.deepEqual(readdirSync(outside), [], 'the escape target is untouched');
  });

  it('a nested symlinked ancestor is refused, naming the offending component', async (t) => {
    const { root, outside } = sandbox(t);
    mkdirSync(join(root, 'a'));
    symlinkSync(outside, join(root, 'a/b'));
    const message = await refused(() => safeWriteFile(root, 'a/b/c.txt', 'x'));
    assert.equal(
      message,
      "refusing 'a/b/c.txt': 'a/b' is a symbolic link; ssd-onboard does not write through symbolic links"
    );
    assert.deepEqual(readdirSync(outside), []);
  });

  it('a final target that is already a symlink to an outside file is not overwritten or removed', async (t) => {
    const { root, outside } = sandbox(t);
    const victim = join(outside, 'victim.txt');
    writeFileSync(victim, 'original\n');
    symlinkSync(victim, join(root, 'file'));

    assert.match(
      await refused(() => safeWriteFile(root, 'file', 'attacker\n')),
      /^refusing 'file': 'file' is a symbolic link; ssd-onboard does not write through symbolic links$/
    );
    assert.equal(readFileSync(victim, 'utf8'), 'original\n', 'the outside file is unchanged');

    assert.match(
      await refused(() => safeRemove(root, 'file')),
      /^refusing 'file': 'file' is a symbolic link; ssd-onboard does not write through symbolic links$/
    );
    assert.ok(existsSync(victim), 'the outside file is not deleted');
    assert.ok(existsSync(join(root, 'file')), 'the link itself is not quietly removed either');
  });

  // Policy: consumer write paths do not traverse symbolic links AT ALL. A link
  // that happens to point back inside the repository is refused just like one
  // that escapes, so there is a single rule with no resolve-and-compare cases.
  it('a symlink pointing INSIDE the repository is refused too (stated policy)', async (t) => {
    const { root } = sandbox(t);
    mkdirSync(join(root, 'real'), { recursive: true });
    symlinkSync(join(root, 'real'), join(root, 'link'));
    assert.match(
      await refused(() => safeWriteFile(root, 'link/inside.txt', 'x')),
      /'link' is a symbolic link; ssd-onboard does not write through symbolic links$/
    );
    assert.ok(!existsSync(join(root, 'real/inside.txt')), 'nothing was written through the link');

    writeFileSync(join(root, 'real/leaf.txt'), 'kept\n');
    symlinkSync(join(root, 'real/leaf.txt'), join(root, 'leaf-link'));
    assert.match(
      await refused(() => safeRemove(root, 'leaf-link')),
      /'leaf-link' is a symbolic link; ssd-onboard does not write through symbolic links$/
    );
    assert.equal(readFileSync(join(root, 'real/leaf.txt'), 'utf8'), 'kept\n');
  });

  it('a non-directory ancestor is refused rather than half-written', async (t) => {
    const { root } = sandbox(t);
    writeFileSync(join(root, 'notadir'), 'x\n');
    assert.equal(
      await refused(() => safeWriteFile(root, 'notadir/child.json', '{}')),
      "refusing 'notadir/child.json': 'notadir' is not a directory"
    );
    assert.equal(readFileSync(join(root, 'notadir'), 'utf8'), 'x\n');
  });

  it('assertSafeRepoPath accepts a missing leaf and a missing subtree', async (t) => {
    const { root } = sandbox(t);
    const target = await assertSafeRepoPath(root, 'does/not/exist/yet.json');
    assert.ok(target.startsWith(root + '/'));
    assert.ok(!existsSync(target));
  });
});

describe('safe-path: removal', () => {
  it('removes an ordinary in-repo file and directory', async (t) => {
    const { root } = sandbox(t);
    await safeWriteFile(root, 'dir/gone.txt', 'x');
    await safeRemove(root, 'dir/gone.txt');
    assert.ok(!existsSync(join(root, 'dir/gone.txt')));
    await safeRemove(root, 'dir', { recursive: true, force: true });
    assert.ok(!existsSync(join(root, 'dir')));
  });

  it('a removal through a symlinked ancestor deletes nothing outside', async (t) => {
    const { root, outside } = sandbox(t);
    writeFileSync(join(outside, 'keep.txt'), 'keep\n');
    symlinkSync(outside, join(root, '.github'));
    assert.match(
      await refused(() => safeRemove(root, '.github/keep.txt', { force: true })),
      /'\.github' is a symbolic link/
    );
    assert.equal(readFileSync(join(outside, 'keep.txt'), 'utf8'), 'keep\n');
    assert.match(
      await refused(() => safeRemove(root, '.github', { recursive: true, force: true })),
      /'\.github' is a symbolic link/
    );
    assert.ok(existsSync(join(outside, 'keep.txt')));
  });
});

// --- through the real onboarding call sites -----------------------------------------

describe('ssd-onboard write paths are confined', () => {
  const cli = async (root, args, io = {}) => {
    const c = capture();
    const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io, ...io });
    return { code, out: c.text(), err: c.errors() };
  };
  const writeConfig = (root, profile, overrides) => write(root, '.ssd/onboarding.yml', serializeConfig(config(profile, overrides)));

  // An `outside` directory that is NOT inside the repository under test.
  const outsideOf = (t) => {
    const dir = join(tempDir(t, 'ssd-confine-outside-'), 'outside');
    mkdirSync(dir, { recursive: true });
    return dir;
  };

  it('render refuses when a generated file path has a symlinked ancestor', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    writeConfig(root, 'source-only');
    symlinkSync(outside, join(root, '.github'));
    const result = await cli(root, ['render']);
    assert.equal(result.code, 1, result.out);
    assert.match(result.err + result.out, /is a symbolic link; ssd-onboard does not write through symbolic links/);
    assert.deepEqual(readdirSync(outside), [], 'no workflow was written outside the repository');
  });

  it('render refuses when an existing generated file was replaced by a symlink', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['render'])).code, 0);

    // The attacker replaces the generated workflow with a link to an outside
    // file holding the PREVIOUS generated bytes (intact marker), so the plan
    // classifies it as a routine `update` and reaches applyWrites.
    const path = '.github/workflows/security.yml';
    const smuggled = join(outside, 'security.yml');
    writeFileSync(smuggled, read(root, path));
    unlinkSync(join(root, path));
    symlinkSync(smuggled, join(root, path));
    writeConfig(root, 'source-only', { semgrep: { rulesets: ['p/owasp-top-ten', 'p/python', 'p/secrets'] } });
    assert.equal((await cli(root, ['render', '--check'])).code, 1, 'the render is a real update');

    const result = await cli(root, ['render']);
    assert.equal(result.code, 1, result.out);
    assert.match(result.err + result.out, /is a symbolic link; ssd-onboard does not write through symbolic links/);
    assert.ok(!readFileSync(smuggled, 'utf8').includes('p/secrets'), 'the outside file is unchanged');
  });

  // applyWrites is sequential and has no rollback: an entry written before the
  // refusal stays written. That is existing, deliberate behaviour and is not
  // what this test is about. The invariant here is narrower and is the security
  // one: the symbolic link is not followed, so the file OUTSIDE the repository
  // is neither written to nor replaced.
  it('applyWrites refuses a symlinked leaf and does not modify the symlink target', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    const victim = join(outside, 'target.yml');
    const original = withMarker('name: original\n');
    writeFileSync(victim, original);
    const victimStat = lstatSync(victim);
    symlinkSync(victim, join(root, 'generated.yml'));
    const plan = await planWrites(root, [
      { path: 'clean.yml', kind: 'workflow', content: withMarker('name: clean\n') },
      { path: 'generated.yml', kind: 'workflow', content: withMarker('name: attacker\n') }
    ]);
    assert.deepEqual(plan.map((e) => e.action), ['create', 'update'], 'the symlinked leaf looks like a routine update');

    await assert.rejects(() => applyWrites(root, plan), (error) => {
      assert.equal(error.name, 'PathConfinementError');
      assert.match(error.message, /'generated\.yml' is a symbolic link/);
      return true;
    });

    const after = lstatSync(victim);
    assert.equal(readFileSync(victim, 'utf8'), original, 'the outside file is unchanged');
    assert.equal(after.ino, victimStat.ino, 'the outside file was not replaced');
    assert.equal(after.mtimeMs, victimStat.mtimeMs, 'the outside file was not rewritten');
    assert.ok(lstatSync(join(root, 'generated.yml')).isSymbolicLink(), 'the link was not followed or replaced');
  });

  it('prune removal refuses a stale path whose ancestor is a symlink', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    mkdirSync(join(outside, 'workflows'), { recursive: true });
    writeFileSync(join(outside, 'workflows/deploy.yml'), 'keep\n');
    symlinkSync(outside, join(root, '.github'));
    await assert.rejects(() => removeFile(root, '.github/workflows/deploy.yml'), /'\.github' is a symbolic link/);
    assert.equal(readFileSync(join(outside, 'workflows/deploy.yml'), 'utf8'), 'keep\n');
  });

  it('init refuses to write .ssd/onboarding.yml through a symlinked .ssd', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    symlinkSync(outside, join(root, '.ssd'));
    const from = join(tempDir(t, 'ssd-confine-partial-'), 'p.yml');
    writeFileSync(from, `profile: source-only\nframework:\n  ref: ${'0'.repeat(40)}\n`);
    const result = await cli(root, ['init', '--non-interactive', '--from', from]);
    assert.notEqual(result.code, 0);
    assert.ok(!existsSync(join(outside, 'onboarding.yml')), 'no config was written outside the repository');
  });

  it('baseline prepare refuses to install a candidate through a symlinked .ssd/candidates', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['render'])).code, 0);
    commitAll(root, 'onboard');
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    const files = bootstrapArtifact(root, cfg, {});
    delete files.provenance;
    const gh = async (args) => {
      if (args[0] === 'api') {
        return JSON.stringify({
          id: 4242, html_url: 'https://github.com/acme/app/actions/runs/4242', event: 'workflow_dispatch',
          status: 'completed', conclusion: 'success', head_branch: 'main', head_sha: head(root),
          path: '.github/workflows/security.yml'
        });
      }
      const dir = args[args.indexOf('--dir') + 1];
      for (const [name, content] of Object.entries(files)) {
        if (content !== null) {
          write(dir, name, content);
        }
      }
      return '';
    };
    rmSync(join(root, CANDIDATE_DIR), { recursive: true, force: true });
    symlinkSync(outside, join(root, CANDIDATE_DIR));

    const result = await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh });
    assert.equal(result.code, 1, result.out);
    assert.match(result.err + result.out, /is a symbolic link; ssd-onboard does not write through symbolic links/);
    assert.deepEqual(readdirSync(outside), [], 'no candidate was written outside the repository');
  });

  it('baseline accept refuses a configured baseline path with a symlinked ancestor, before writing', async (t) => {
    const root = makeRepo(t, PY_REPO);
    const outside = outsideOf(t);
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['render'])).code, 0);
    commitAll(root, 'onboard');
    const cfg = parseConfig(read(root, '.ssd/onboarding.yml')).config;
    const files = bootstrapArtifact(root, cfg, {});
    delete files.provenance;
    const gh = async (args) => {
      if (args[0] === 'api') {
        return JSON.stringify({
          id: 4242, html_url: 'https://github.com/acme/app/actions/runs/4242', event: 'workflow_dispatch',
          status: 'completed', conclusion: 'success', head_branch: 'main', head_sha: head(root),
          path: '.github/workflows/security.yml'
        });
      }
      const dir = args[args.indexOf('--dir') + 1];
      for (const [name, content] of Object.entries(files)) {
        if (content !== null) {
          write(dir, name, content);
        }
      }
      return '';
    };
    assert.equal((await cli(root, ['baseline', 'prepare', '--run', '4242'], { gh })).code, 0);

    // Only now does the checkout grow the hostile component: `security` is the
    // first component of the configured baseline path.
    symlinkSync(outside, join(root, 'security'));
    const result = await cli(root, ['baseline', 'accept', '--yes', '--expect-findings', '2'], { gh });
    assert.equal(result.code, 1, result.out);
    assert.match(result.err + result.out, /'security' is a symbolic link/);
    assert.deepEqual(readdirSync(outside), [], 'no baseline was written outside the repository');
    assert.ok(existsSync(join(root, CANDIDATE_FILE)), 'the candidate is not removed by a refused accept');
    assert.equal(
      parseConfig(read(root, '.ssd/onboarding.yml')).config.semgrep.baseline.state,
      'absent',
      'the refused accept did not flip the baseline state'
    );
  });

  it('an ordinary repository still onboards end to end (the guard is not a blanket refusal)', async (t) => {
    const root = makeRepo(t, PY_REPO);
    writeConfig(root, 'source-only');
    assert.equal((await cli(root, ['render'])).code, 0);
    assert.ok(existsSync(join(root, '.github/workflows/security.yml')));
    assert.ok(existsSync(join(root, '.ssd/onboarding.yml')));
    assert.equal((await cli(root, ['render', '--check'])).code, 0);
  });
});
