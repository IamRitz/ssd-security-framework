// The test fixtures must not leak temporary directories.
//
// `makeRepo()` creates a git repository per test; `node --test` runs the
// onboarding suite hundreds of times per change. Roots that are never removed
// exhausted /tmp's INODES (not its bytes) on a developer machine: ~13k leaked
// `ssd-onboard-*` roots holding ~1M filesystem objects, after which every
// mkdtemp in the process failed with ENOSPC. These tests pin the ownership
// model down so it cannot regress.
//
// Every check is scoped to roots this file created. Nothing here reads or
// deletes anything outside its own sandbox, and nothing asserts on a global
// count of `ssd-onboard-*` directories, so a concurrent onboarding test file
// creating its own fixtures can never affect the result.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import { TEMP_PREFIX, makeRepo, tempDir } from './support/onboarding-fixtures.mjs';

// This file's own sandbox. os.tmpdir() reads TMPDIR on every call, so pointing
// it here makes the fixture create its roots inside the sandbox and nowhere
// else — the only way to assert "no fixture directory remains" without making
// a claim about /tmp as a whole.
const SANDBOX = mkdtempSync(join(tmpdir(), 'ssd-fixture-lifecycle-'));
after(() => rmSync(SANDBOX, { recursive: true, force: true }));

// A stand-in for a node:test context, so a test can run the cleanup hooks the
// fixture registered and observe the result within one test.
function registrar() {
  const hooks = [];
  return { t: { after: (fn) => hooks.push(fn) }, run: () => hooks.splice(0).forEach((fn) => fn()) };
}

function inSandbox(fn) {
  const previous = process.env.TMPDIR;
  process.env.TMPDIR = SANDBOX;
  try {
    return fn();
  } finally {
    if (previous === undefined) {
      delete process.env.TMPDIR;
    } else {
      process.env.TMPDIR = previous;
    }
  }
}

const fixtureDirs = () => readdirSync(SANDBOX).filter((name) => name.startsWith(TEMP_PREFIX));

describe('fixture temp directories are owned by the test that created them', () => {
  it('every root created by a test is gone once its cleanup hooks run', () => {
    const { t, run } = registrar();
    const roots = inSandbox(() => [makeRepo(t, { 'a.txt': 'a\n' }), makeRepo(t, { 'b/c.txt': 'c\n' }), tempDir(t)]);
    assert.equal(new Set(roots).size, 3, 'each call gets its own root');
    for (const root of roots) {
      assert.ok(existsSync(root), `${root} exists while the test owns it`);
    }
    assert.equal(fixtureDirs().length, 3);

    run();

    for (const root of roots) {
      assert.ok(!existsSync(root), `${root} was removed`);
    }
    assert.deepEqual(fixtureDirs(), [], 'no fixture directory accumulates in the sandbox');
  });

  it('a root is removed even when the fixture throws half-built', () => {
    const { t, run } = registrar();
    // 'a' is a file, so creating 'a/b' fails AFTER mkdtemp created the root.
    assert.throws(() => inSandbox(() => makeRepo(t, { a: 'file\n', 'a/b': 'under a file\n' })), /ENOTDIR|EEXIST/);
    assert.deepEqual(fixtureDirs(), [], 'the half-built root is removed by the fixture itself, before the hook runs');
    run(); // The hook is registered too, and removing an absent root is a no-op.
    assert.deepEqual(fixtureDirs(), []);
  });

  it('the fixture refuses to create a directory nobody owns', () => {
    assert.throws(() => makeRepo(), /pass the test context/);
    assert.throws(() => makeRepo({ 'a.txt': 'a\n' }), /pass the test context/);
    assert.throws(() => tempDir({}), /pass the test context/);
    assert.deepEqual(fixtureDirs(), [], 'a refused call creates nothing');
  });

  // Cleanup does not hide a genuine failure: rmSync is called without a
  // try/catch, so a root that cannot be removed fails the owning test. Only the
  // already-removed case is tolerated, and that is what force: true is for.
  it('a root removed by the test itself does not make cleanup fail', () => {
    const { t, run } = registrar();
    const root = inSandbox(() => tempDir(t));
    writeFileSync(join(root, 'x'), 'x\n');
    rmSync(root, { recursive: true, force: true });
    run();
    assert.deepEqual(fixtureDirs(), []);
  });
});

// Proof against the REAL node:test lifecycle rather than a stand-in: the first
// test records its roots, the second — which runs after it, because tests in a
// file are sequential — asserts they are gone.
describe('the real node:test lifecycle removes fixture roots', () => {
  const recorded = [];

  it('creates fixture roots and records their exact paths', (t) => {
    recorded.push(inSandbox(() => makeRepo(t, { 'a.txt': 'a\n' })), inSandbox(() => tempDir(t, 'ssd-onboard-extra-')));
    for (const root of recorded) {
      assert.ok(existsSync(root));
    }
  });

  it('every recorded root no longer exists once the owning test has finished', () => {
    assert.equal(recorded.length, 2, 'the previous test ran');
    for (const root of recorded) {
      assert.ok(!existsSync(root), `${root} was removed by t.after`);
    }
  });
});
