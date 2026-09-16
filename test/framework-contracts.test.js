// Structural guards on the FRAMEWORK's own workflows.
//
// Two classes of regression are invisible at runtime and so are asserted here:
//
//  1. The credential boundary — a `secrets: inherit` or an `id-token` added "to
//     make it work" fails nothing and looks green.
//  2. THE EXTRACTION ITSELF — every reusable workflow must load its scripts from
//     the toolkit it checks out, and must move that toolkit out of the scanned
//     workspace first. A single `node security/scripts/...` reintroduces the
//     coupling that made these workflows unusable outside their home repo, and
//     a missing relocation silently starts scanning the framework's own code as
//     if it were the consumer's.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const WORKFLOW_DIR = '.github/workflows';

const read = (file) => readFileSync(join(WORKFLOW_DIR, file), 'utf8');
// Comments explain these rules; only the executable body is asserted against them.
const readExecutable = (file) =>
  read(file)
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');

const REUSABLE = readdirSync(WORKFLOW_DIR).filter(
  (name) => name.startsWith('_') && name.endsWith('.yml')
);

// Reusable workflows that must never hold cloud credentials. `_ecr-collect.yml`
// is the registry adapter; `_source-security.yml`'s gate job may assume the
// narrowly scoped break-glass invoker role after eligibility is confirmed.
const CREDENTIAL_FREE = ['_image-scan-prepush.yml', '_artifact-gate.yml', '_conformance.yml'];

describe('the framework ships the expected reusable workflows', () => {
  it('has all five, and they are workflow_call only', () => {
    assert.deepEqual(REUSABLE.sort(), [
      '_artifact-gate.yml',
      '_conformance.yml',
      '_ecr-collect.yml',
      '_image-scan-prepush.yml',
      '_source-security.yml'
    ]);
    for (const file of REUSABLE) {
      const source = readExecutable(file);
      assert.match(source, /^on:\n {2}workflow_call:/m, `${file} must be workflow_call only`);
      for (const trigger of ['push:', 'pull_request:', 'schedule:']) {
        assert.ok(
          !new RegExp(`^ {2}${trigger}`, 'm').test(source),
          `${file} must not declare its own ${trigger} trigger`
        );
      }
    }
  });
});

describe('the toolkit no longer travels with the consumer', () => {
  for (const file of REUSABLE) {
    it(`${file} runs every script from the checked-out toolkit`, () => {
      const source = readExecutable(file);

      // The regression this guards: a path resolved against the CALLING repo's
      // checkout, which only works inside the framework's own repository.
      const consumerRelative = [...source.matchAll(/node\s+["']?(?!\$)([A-Za-z0-9_./-]*scripts\/[A-Za-z0-9_.-]+\.mjs)/g)];
      assert.deepEqual(
        consumerRelative.map((match) => match[1]),
        [],
        `${file} invokes a script by a consumer-relative path; it must use "$SSD_TOOLKIT/scripts/..."`
      );
    });

    it(`${file} checks the framework out and pins a non-empty ref`, () => {
      const source = readExecutable(file);
      assert.match(source, /repository: \$\{\{ inputs\.toolkit_repository \}\}/, 'must check out the toolkit repo');
      assert.match(source, /ref: \$\{\{ inputs\.toolkit_ref \}\}/, 'must check out at the toolkit ref');
      // An empty ref would silently resolve to the framework's default branch —
      // an unpinned, moving dependency in a security control.
      assert.match(
        source,
        /toolkit_ref is empty/,
        'must refuse to resolve the toolkit from a default branch'
      );
    });

    it(`${file} asserts the toolkit's major version`, () => {
      const source = readExecutable(file);
      assert.match(source, /SSD_REQUIRED_TOOLKIT_MAJOR/, 'must declare the major it is written against');
      assert.match(source, /VERSION/, 'must read the toolkit VERSION file');
    });

    it(`${file} moves the toolkit out of the scanned workspace`, () => {
      // The workspace must be byte-identical to the consumer's own checkout when
      // scanners run. Semgrep's default path is `.` and OSV-Scanner walks the
      // tree recursively; a toolkit left in place is scanned as consumer code.
      const source = readExecutable(file);
      assert.match(
        source,
        /mv \.ssd-toolkit-checkout "\$RUNNER_TEMP\/ssd-toolkit"/,
        `${file} must relocate the toolkit under RUNNER_TEMP`
      );
    });
  }

  it('the scanning workflow proves the workspace is clean before scanning', () => {
    // Only _source-security.yml runs scanners over the workspace, so it carries
    // the explicit assertion.
    const source = readExecutable('_source-security.yml');
    const assertions = source.match(/Confirm the workspace holds no framework files/g) ?? [];
    assert.equal(
      assertions.length,
      3,
      'each of the three scanner jobs must assert the workspace holds no framework files'
    );
  });
});

describe('the credential boundary', () => {
  for (const file of CREDENTIAL_FREE) {
    it(`${file} can assume no cloud role`, () => {
      const source = readExecutable(file);
      // `id-token: write` is what makes OIDC role assumption possible at all.
      assert.ok(!/id-token\s*:/.test(source), 'must not request an id-token');
      assert.ok(!/aws-actions\//.test(source), 'must not use an aws-actions action');
      assert.ok(!/role-to-assume/.test(source), 'must not assume a role');
    });
  }

  it('only approved workflows assume cloud roles', () => {
    const assuming = REUSABLE.filter((file) => /role-to-assume/.test(read(file)));
    assert.deepEqual(assuming.sort(), ['_ecr-collect.yml', '_source-security.yml']);
  });

  it('source-security loads no approval credential before confirming eligibility', () => {
    const source = readExecutable('_source-security.yml');
    const gate = source.slice(source.indexOf('  source-gate:'));
    const eligibility = gate.indexOf('Confirm the BLOCK is eligible before loading any approval credential');
    const oidc = gate.indexOf('Assume the break-glass invoker role (OIDC)');
    assert.ok(eligibility >= 0, 'eligibility check is missing');
    assert.ok(oidc >= 0, 'OIDC role-assumption step is missing');
    assert.ok(eligibility < oidc, 'OIDC credentials must only be loaded after eligibility is confirmed');
  });

  it('no workflow uses `secrets: inherit`', () => {
    for (const file of readdirSync(WORKFLOW_DIR).filter((name) => name.endsWith('.yml'))) {
      assert.ok(
        !/secrets\s*:\s*inherit/.test(readExecutable(file)),
        `${file} must not pass every repo secret into a called workflow`
      );
    }
  });

  it('only source-security declares a secret, and only the break-glass one', () => {
    const source = read('_source-security.yml');
    const declared = [...source.matchAll(/^ {6}([a-z0-9_]+):\s*$/gm)]
      .map((match) => match[1])
      .filter((name) => source.includes(`secrets:\n      ${name}:`));
    assert.deepEqual(declared, ['break_glass_shared_secret']);
    for (const file of CREDENTIAL_FREE) {
      assert.ok(!/^ {4}secrets:/m.test(read(file)), `${file} must accept no secrets`);
    }
  });
});

describe('the artifact gate stays registry-neutral', () => {
  it('names no registry, so swapping registries touches only the collector', () => {
    const executable = readExecutable('_artifact-gate.yml');
    for (const term of [/\becr\b/i, /\bamazon\b/i, /\bgcr\b/i, /\backr\b/i, /\bdockerhub\b/i]) {
      assert.ok(!term.test(executable), `artifact gate must not reference ${term}`);
    }
  });
});

describe('capability declaration', () => {
  it('conformance accepts the three declared capabilities', () => {
    const source = readExecutable('_conformance.yml');
    for (const input of ['artifact_type:', 'registry:', 'deploy_target:']) {
      assert.match(source, new RegExp(`^ {6}${input}`, 'm'), `_conformance.yml must accept ${input}`);
    }
  });

  it('requires observed results rather than assuming controls ran', () => {
    const source = readExecutable('_conformance.yml');
    assert.match(source, /observed:[\s\S]*?required: true/, 'observed results must be required');
  });
});

describe('the example callers keep their two version pins in sync', () => {
  // A reusable workflow cannot read its own ref, so a consumer states the
  // version twice: once in `uses: ...@v1` and once as `toolkit_ref: v1`. Drift
  // between them runs one version's workflow against another version's scripts.
  // The shipped examples are what people copy, so they are the one place this
  // must never be wrong.
  const EXAMPLE_DIR = 'examples';
  const examples = readdirSync(EXAMPLE_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .filter((entry) => readdirSync(join(EXAMPLE_DIR, entry.name)).includes('security.yml'))
    .map((entry) => join(EXAMPLE_DIR, entry.name, 'security.yml'));

  it('has example callers to check', () => {
    assert.ok(examples.length >= 3, 'expected at least three example callers');
  });

  for (const path of examples) {
    it(`${path} pins one ref in both places`, () => {
      const source = readFileSync(path, 'utf8');
      const usesRefs = [
        ...source.matchAll(/uses:\s*\S*ssd-security-framework\/\.github\/workflows\/\S+@(\S+)/g)
      ].map((match) => match[1]);
      const toolkitRefs = [...source.matchAll(/toolkit_ref:\s*(\S+)/g)].map((match) => match[1]);

      assert.ok(usesRefs.length > 0, 'example must call the framework');
      const distinct = [...new Set(usesRefs)];
      assert.equal(distinct.length, 1, `example mixes framework refs: ${distinct.join(', ')}`);
      assert.equal(
        toolkitRefs.length,
        usesRefs.length,
        'every framework call must pass toolkit_ref'
      );
      for (const ref of toolkitRefs) {
        assert.equal(ref, distinct[0], `toolkit_ref '${ref}' must match the uses: ref`);
      }
    });
  }
});
