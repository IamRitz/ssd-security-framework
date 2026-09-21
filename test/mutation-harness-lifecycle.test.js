// The mutation harness must not leak temporary repository copies.
//
// `tools/mutation-check-onboarding.mjs` copies the whole repository once for the
// pristine run and once per mutation. The per-mutant copies were always removed
// in a `finally`, but the pristine copy was removed by a bare statement AFTER a
// `process.exit(1)` that fired when the unmutated suite failed: every aborted
// run left one full repository copy behind. These tests pin the ownership model
// down — every root the harness creates is gone on every exit path.
//
// Everything here runs against a throwaway fixture repository inside this
// file's own sandbox, never against the real suite, and every assertion is
// scoped to that sandbox. Nothing reads or deletes anything under /tmp at
// large, and no assertion depends on a global count of `ssd-mutant-*`
// directories, so concurrent runs cannot affect the result.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import { TEMP_PREFIX, copyRepo, killSummary, runMutationCheck } from '../tools/mutation-check-onboarding.mjs';

const SANDBOX = mkdtempSync(join(tmpdir(), 'ssd-mutant-lifecycle-'));
after(() => rmSync(SANDBOX, { recursive: true, force: true }));

// A stand-in repository: one source file and one test that asserts its value,
// so a mutation of the source is killed and a mutation of a comment survives.
function fixtureRepo() {
  const root = mkdtempSync(join(SANDBOX, 'fixture-'));
  mkdirSync(join(root, 'lib'));
  writeFileSync(join(root, 'lib/invariant.mjs'), "export const ENFORCED = true;\n// a comment\n");
  writeFileSync(
    join(root, 'check.test.js'),
    "import assert from 'node:assert/strict';\nimport { test } from 'node:test';\nimport { ENFORCED } from './lib/invariant.mjs';\ntest('enforced', () => assert.equal(ENFORCED, true));\n"
  );
  return root;
}

// The roots the harness created inside the sandbox and did not remove. Only
// this file's sandbox is inspected, and only by the harness's own prefix.
const leaked = () => readdirSync(SANDBOX).filter((name) => name.startsWith(TEMP_PREFIX));

// The harness reads a child `node --test` run's exit status. Inside this file's
// own `node --test` run, NODE_TEST_CONTEXT is set and would be inherited by
// that grandchild, which then reports to its parent instead of exiting
// non-zero. Unsetting it for the call reproduces how the harness is really run.
function asStandaloneRun(fn) {
  const previous = process.env.NODE_TEST_CONTEXT;
  delete process.env.NODE_TEST_CONTEXT;
  try {
    return fn();
  } finally {
    if (previous !== undefined) process.env.NODE_TEST_CONTEXT = previous;
  }
}

const run = (options) => {
  const lines = [];
  const code = asStandaloneRun(() =>
    runMutationCheck({ parent: SANDBOX, log: (l) => lines.push(l), logError: (l) => lines.push(l), ...options })
  );
  return { code, output: lines.join('\n') };
};

describe('the mutation harness owns every temp root it creates', () => {
  it('a successful run leaves no temp root behind', () => {
    const source = fixtureRepo();
    const { code, output } = run({
      source,
      tests: ['check.test.js'],
      mutations: [['the invariant is enforced', 'lib/invariant.mjs', 'ENFORCED = true', 'ENFORCED = false']]
    });
    assert.equal(code, 0);
    assert.match(output, /1\/1 mutations killed/);
    assert.deepEqual(leaked(), []);
  });

  // The old leak: the pristine suite fails before any mutation runs. The suite
  // itself is untouched — this fixture simply has no such test file, so
  // `node --test` exits non-zero exactly as a genuinely red suite would.
  it('a failing pristine suite leaves no temp root behind', () => {
    const source = fixtureRepo();
    const { code, output } = run({ source, tests: ['no-such.test.js'], mutations: [] });
    assert.equal(code, 1, 'the failure is still reported');
    assert.match(output, /The unmutated suite fails/);
    assert.deepEqual(leaked(), [], 'the pristine copy is removed even though the run aborted');
  });

  it('a surviving mutation leaves no temp root behind', () => {
    const source = fixtureRepo();
    const { code, output } = run({
      source,
      tests: ['check.test.js'],
      mutations: [['a comment is load-bearing', 'lib/invariant.mjs', '// a comment', '// another comment']]
    });
    assert.equal(code, 1);
    assert.match(output, /SURVIVED/);
    assert.deepEqual(leaked(), []);
  });

  it('a stale mutation target leaves no temp root behind', () => {
    const source = fixtureRepo();
    const { code, output } = run({
      source,
      tests: ['check.test.js'],
      mutations: [['a target that no longer exists', 'lib/invariant.mjs', 'NOT PRESENT', 'x']]
    });
    assert.equal(code, 1);
    assert.match(output, /STALE/);
    assert.deepEqual(leaked(), [], 'the `continue` path unwinds through the finally');
  });

  it('a mutation that throws leaves no temp root behind', () => {
    const source = fixtureRepo();
    assert.throws(
      () =>
        run({
          source,
          tests: ['check.test.js'],
          mutations: [['a file that is not there', 'lib/absent.mjs', 'a', 'b']]
        }),
      /ENOENT/
    );
    assert.deepEqual(leaked(), [], 'both the mutant and the pristine copy are removed while the error propagates');
  });

  it('a copy that fails half-built removes its own root before rethrowing', () => {
    const source = join(fixtureRepo(), 'check.test.js'); // A file, not a directory.
    assert.throws(() => copyRepo(source, SANDBOX));
    assert.deepEqual(leaked(), [], 'the root mkdtemp created is removed by copyRepo itself');
  });

  it('copies land under TMPDIR rather than a hardcoded /tmp', () => {
    const previous = process.env.TMPDIR;
    process.env.TMPDIR = SANDBOX;
    let root;
    try {
      root = copyRepo(fixtureRepo());
    } finally {
      if (previous === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previous;
    }
    try {
      assert.equal(root.startsWith(join(SANDBOX, TEMP_PREFIX)), true, `${root} is inside TMPDIR`);
      assert.ok(existsSync(join(root, 'lib/invariant.mjs')), 'the copy holds the repository contents');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
    assert.deepEqual(leaked(), []);
  });
});

// A kill is proved by the child's non-zero exit status; the failure count is
// only how that kill is PRINTED. GitHub's runner printed `undefined test(s)
// failed` because the count was read from stdout alone, in the one shape the
// TAP reporter uses.
describe('a killed mutation is reported without inventing anything', () => {
  it('reads `# fail N` from the TAP reporter', () => {
    assert.equal(killSummary({ status: 1, stdout: '# tests 12\n# pass 9\n# fail 3\n', stderr: '' }), '3 test(s) failed');
  });

  it('reads the spec reporter\'s `fail N`, and reads stderr as well as stdout', () => {
    assert.equal(killSummary({ status: 1, stdout: '', stderr: 'ℹ tests 12\nℹ pass 9\nℹ fail 3\n' }), '3 test(s) failed');
    assert.equal(killSummary({ status: 1, stdout: 'ℹ fail 2\n', stderr: '' }), '2 test(s) failed');
  });

  it('falls back to the exit status when no count can be parsed — never `undefined`', () => {
    for (const result of [
      { status: 1, stdout: 'something else entirely\n', stderr: '' },
      { status: 7, stdout: '', stderr: '' },
      { status: 1 },
      {}
    ]) {
      const summary = killSummary(result);
      assert.doesNotMatch(summary, /undefined/, JSON.stringify(result));
      assert.match(summary, /^(\d+ test\(s\) failed|test suite exited .+)$/);
    }
    assert.equal(killSummary({ status: 1, stdout: 'no counts here\n', stderr: '' }), 'test suite exited 1');
    assert.equal(killSummary({ status: null, signal: 'SIGKILL' }), 'test suite exited SIGKILL');
    assert.equal(killSummary({ status: null }), 'test suite exited non-zero');
  });

  it('a real killed mutation prints a count and never the string `undefined`', () => {
    const source = fixtureRepo();
    const { code, output } = run({
      source,
      tests: ['check.test.js'],
      mutations: [['the invariant is enforced', 'lib/invariant.mjs', 'ENFORCED = true', 'ENFORCED = false']]
    });
    assert.equal(code, 0);
    assert.match(output, /^killed   the invariant is enforced — 1 test\(s\) failed$/m);
    assert.doesNotMatch(output, /undefined/);
  });

  // The reporting change must not touch the judgement: non-zero is a kill,
  // zero is a survivor, and a stale target is still a survivor.
  it('kill / survive / stale semantics are unchanged', () => {
    const source = fixtureRepo();
    const killed = run({ source, tests: ['check.test.js'], mutations: [['killed', 'lib/invariant.mjs', 'ENFORCED = true', 'ENFORCED = false']] });
    assert.deepEqual([killed.code, /1\/1 mutations killed/.test(killed.output)], [0, true]);
    const survived = run({ source, tests: ['check.test.js'], mutations: [['survivor', 'lib/invariant.mjs', '// a comment', '// other']] });
    assert.deepEqual([survived.code, /SURVIVED/.test(survived.output), /0\/1 mutations killed/.test(survived.output)], [1, true, true]);
    const stale = run({ source, tests: ['check.test.js'], mutations: [['stale', 'lib/invariant.mjs', 'NOT PRESENT', 'x']] });
    assert.deepEqual([stale.code, /STALE/.test(stale.output), /0\/1 mutations killed/.test(stale.output)], [1, true, true]);
  });
});
