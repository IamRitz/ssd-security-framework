// CODEOWNERS coverage of the security-owned paths. The matcher answers one
// question — does every file under this path have an effective owner? — and
// must never answer yes when GitHub would not: the last matching rule wins, an
// ownerless rule un-owns what it matches, `/*` is top-level only, and a pattern
// it cannot evaluate proves nothing.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { analyze, codeownersCovers, securityOwnedPaths } from '../onboarding/lib/analyze.mjs';
import { inspectRepository } from '../onboarding/lib/inspect.mjs';
import { FRAMEWORK, config, makeRepo } from './support/onboarding-fixtures.mjs';

const BASELINE = 'security/baseline/semgrep-baseline.json';
const SSD = '.ssd/';
const WORKFLOWS = '.github/workflows/';
const WORKFLOW = '.github/workflows/security.yml';
const OWNED = [SSD, WORKFLOWS, BASELINE, '.semgrepignore'];

const covers = (lines, path) => codeownersCovers(lines.join('\n'), path);

describe('CODEOWNERS: what a rule covers', () => {
  it('`*` covers every security-owned path, nested ones included', () => {
    for (const path of [...OWNED, WORKFLOW, '.ssd/onboarding.yml']) {
      assert.equal(covers(['* @sec'], path), true, path);
    }
  });

  it('`/*` covers top-level files only, never nested paths', () => {
    assert.equal(covers(['/* @sec'], '.semgrepignore'), true);
    for (const path of [WORKFLOW, WORKFLOWS, SSD, BASELINE]) {
      assert.equal(covers(['/* @sec'], path), false, path);
    }
  });

  it('`**` and `/**` cover everything', () => {
    for (const pattern of ['**', '/**']) {
      for (const path of [...OWNED, WORKFLOW]) {
        assert.equal(covers([`${pattern} @sec`], path), true, `${pattern} ${path}`);
      }
    }
  });

  it('a directory rule covers the directory, anchored or not', () => {
    for (const pattern of ['/.github/workflows/', '.github/workflows/', '/.github/workflows', 'workflows/', '/.github/', '/.github/**']) {
      assert.equal(covers([`${pattern} @sec`], WORKFLOWS), true, pattern);
      assert.equal(covers([`${pattern} @sec`], WORKFLOW), true, pattern);
    }
    assert.equal(covers(['/security/baseline/ @sec'], BASELINE), true);
    assert.equal(covers(['/.ssd/ @sec'], SSD), true);
  });

  it('an exact file rule covers that file and nothing else', () => {
    assert.equal(covers([`/${BASELINE} @sec`], BASELINE), true);
    assert.equal(covers(['/.semgrepignore @sec'], '.semgrepignore'), true);
    assert.equal(covers([`/${BASELINE} @sec`], 'security/baseline/'), false);
    assert.equal(covers(['/.ssd/onboarding.yml @sec'], SSD), false, 'one file does not own the directory');
  });

  it('a directory rule on another root does not cover', () => {
    assert.equal(covers(['/src/.github/workflows/ @sec'], WORKFLOWS), false);
    assert.equal(covers(['/docs/ @sec'], SSD), false);
  });

  it('a wildcard final segment is not recursive: `.github/workflows/*` does not prove the directory', () => {
    assert.equal(covers(['.github/workflows/* @sec'], WORKFLOWS), false);
    assert.equal(covers(['.github/workflows/* @sec'], WORKFLOW), true, 'a file directly inside is matched');
    assert.equal(covers(['/.ssd/*.yml @sec'], SSD), false);
  });
});

describe('CODEOWNERS: the last matching rule wins', () => {
  it('a later ownerless rule removes ownership', () => {
    const lines = ['* @sec', '.ssd/onboarding.yml'];
    assert.equal(covers(lines, '.ssd/onboarding.yml'), false);
    assert.equal(covers(lines, SSD), false, 'a directory with an un-owned file is not covered');
    assert.equal(covers(lines, WORKFLOWS), true, 'the ownerless rule does not touch other paths');
  });

  it('a later ownerless directory or wildcard rule removes ownership of what it may match', () => {
    assert.equal(covers(['* @sec', '.ssd/'], SSD), false);
    assert.equal(covers(['* @sec', '/.github/'], WORKFLOWS), false);
    assert.equal(covers(['* @sec', '*.yml'], WORKFLOWS), false);
    assert.equal(covers(['* @sec', '*.yml'], '.semgrepignore'), true);
    assert.equal(covers(['/.ssd/ @sec', 'README.md'], SSD), false, 'an unanchored name matches at any depth, .ssd/README.md included');
  });

  it('a later rule WITH owners keeps the path owned', () => {
    const lines = ['* @team-a', '.ssd/onboarding.yml @org/team-b'];
    assert.equal(covers(lines, '.ssd/onboarding.yml'), true);
    assert.equal(covers(lines, SSD), true);
  });

  it('an unrelated later rule does not remove coverage', () => {
    for (const later of ['/docs/', '/src/ @app', '/README.md', '/src/*.py']) {
      assert.equal(covers(['/.ssd/ @sec', later], SSD), true, later);
      assert.equal(covers(['/.github/workflows/ @sec', later], WORKFLOWS), true, later);
    }
  });

  it('an owner rule AFTER an ownerless rule restores coverage', () => {
    assert.equal(covers(['.ssd/', '/.ssd/ @sec'], SSD), true);
  });

  it('an ownerless rule on its own covers nothing', () => {
    for (const path of OWNED) {
      assert.equal(covers(['*'], path), false, path);
    }
  });
});

describe('CODEOWNERS: syntax', () => {
  it('comments and blank lines are ignored; an inline comment is not an owner', () => {
    const text = ['# security', '', '   ', '/.ssd/ @sec # the config', '# /.github/workflows/ @sec', ''];
    assert.equal(covers(text, SSD), true);
    assert.equal(covers(text, WORKFLOWS), false, 'a commented-out rule is not a rule');
    assert.equal(covers(['/.ssd/ # @sec'], SSD), false, 'an owner after # is a comment');
  });

  it('an owner must be @user, @org/team or an email', () => {
    assert.equal(covers(['/.ssd/ @sec'], SSD), true);
    assert.equal(covers(['/.ssd/ @acme/sec-team'], SSD), true);
    assert.equal(covers(['/.ssd/ sec@example.com'], SSD), true);
    assert.equal(covers(['/.ssd/ nobody'], SSD), false);
    assert.equal(covers(['/.ssd/ @sec nobody'], SSD), false, 'a line with a malformed owner proves nothing');
    assert.equal(covers(['* @sec', '/.ssd/ nobody'], SSD), false, 'and is treated as removing ownership');
  });

  it('a malformed or unsupported pattern never produces coverage', () => {
    for (const pattern of ['/', '//', '[.]ssd/', '!.ssd/', '\\.ssd/', '/.ssd/../', '/./.ssd/', '.s**d/', '[Section]']) {
      assert.equal(covers([`${pattern} @sec`], SSD), false, pattern);
    }
  });

  it('an ownerless pattern it cannot evaluate is assumed to match', () => {
    assert.equal(covers(['* @sec', '[.]ssd/'], SSD), false);
    assert.equal(covers(['* @sec', '[Section]'], WORKFLOWS), false);
  });

  it('the shipped example covers every security-owned path', async () => {
    const { readFile } = await import('node:fs/promises');
    const text = await readFile(new URL('../examples/CODEOWNERS.example', import.meta.url), 'utf8');
    for (const path of securityOwnedPaths(config('source-only'))) {
      assert.equal(codeownersCovers(text, path), true, path);
    }
  });
});

describe('CODEOWNERS: analyze does not over-claim', () => {
  async function codeownersWarnings(t, text) {
    const root = makeRepo(t, { 'src/app.py': 'print("hi")\n', 'requirements.txt': 'requests==2.32.5\n', '.github/CODEOWNERS': text });
    const result = await analyze({ root, config: config('source-only'), facts: await inspectRepository(root), framework: FRAMEWORK });
    return result.warnings.filter((w) => w.area === 'codeowners').map((w) => w.message);
  }

  it('`/*` leaves the nested security paths reported as uncovered', async (t) => {
    const [message] = await codeownersWarnings(t, '/* @acme/sec\n');
    assert.match(message, /\.github\/CODEOWNERS does not cover: \.ssd\/ \.github\/workflows\/ security\/baseline\/semgrep-baseline\.json$/);
  });

  it('a later ownerless rule leaves its path reported as uncovered', async (t) => {
    const [message] = await codeownersWarnings(t, '* @acme/sec\n.ssd/onboarding.yml\n');
    assert.match(message, /does not cover: \.ssd\/$/);
  });

  it('complete coverage produces no CODEOWNERS warning', async (t) => {
    assert.deepEqual(await codeownersWarnings(t, `/.ssd/ @acme/sec\n/.github/workflows/ @acme/sec\n/${BASELINE} @acme/sec\n/.semgrepignore @acme/sec\n`), []);
  });
});
