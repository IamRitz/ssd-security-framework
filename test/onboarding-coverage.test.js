// ssd-onboard coverage analysis. Every "covered" claim here must correspond to
// a scanner the framework actually runs on that file; see
// docs/onboarding-architecture.md Part A for the verification against the
// pinned scanner images.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  SEMGREP_IMPLICIT_IGNORES,
  analyzeGitleaksToml,
  analyzeTrufflehogExcludes,
  classifyManifests,
  compileIgnore,
  dependencyFindings,
  isIgnored,
  semgrepScope,
  suggestIgnores,
  suggestRulesets
} from '../onboarding/lib/coverage.mjs';

function classify(files) {
  const texts = Object.fromEntries(Object.entries(files).filter(([, v]) => typeof v === 'string'));
  const { manifests } = classifyManifests(Object.keys(files), (path) => texts[path] ?? null);
  return Object.fromEntries(manifests.map((m) => [m.path, m.coverage]));
}

const PKG_WITH_DEPS = JSON.stringify({ name: 'x', dependencies: { lodash: '4.17.15' } });
const PKG_NO_DEPS = JSON.stringify({ name: 'x', scripts: { test: 'node --test' } });

describe('dependency layout: root', () => {
  it('root package-lock.json and requirements.txt get the native scanner AND OSV-Scanner', () => {
    assert.deepEqual(classify({ 'package-lock.json': '{}', 'requirements.txt': '' }), {
      'package-lock.json': 'native+osv',
      'requirements.txt': 'native+osv'
    });
  });

  it('a root package.json is covered through its lockfile', () => {
    assert.equal(classify({ 'package.json': PKG_WITH_DEPS, 'package-lock.json': '{}' })['package.json'], 'covered-by-lockfile');
  });

  it('ecosystems with no native scanner are OSV-covered, not a gap', () => {
    const result = classify({ 'go.mod': '', 'Cargo.lock': '', 'Gemfile.lock': '' });
    assert.deepEqual(Object.values(result), ['osv', 'osv', 'osv']);
  });
});

describe('dependency layout: what must NOT be reported as covered', () => {
  it('a nested package-lock.json / requirements.txt is OSV-only: the native scanner reads the root only', () => {
    const result = classify({ 'svc/api/package-lock.json': '{}', 'svc/py/requirements.txt': '' });
    assert.equal(result['svc/api/package-lock.json'], 'osv-only');
    assert.equal(result['svc/py/requirements.txt'], 'osv-only');
  });

  it('a root yarn.lock / poetry.lock is OSV-only (npm audit / pip-audit never read them)', () => {
    const result = classify({ 'yarn.lock': '', 'poetry.lock': '' });
    assert.deepEqual(Object.values(result), ['osv-only', 'osv-only']);
  });

  it('a package.json that declares dependencies and has no lockfile is scanned by NOTHING', () => {
    assert.equal(classify({ 'package.json': PKG_WITH_DEPS })['package.json'], 'uncovered');
    assert.equal(classify({ 'web/package.json': PKG_WITH_DEPS })['web/package.json'], 'uncovered');
  });

  it('a pyproject.toml with dependencies and no lockfile is scanned by nothing', () => {
    const pyproject = '[project]\nname = "x"\ndependencies = [\n  "requests==2.19.1",\n]\n';
    assert.equal(classify({ 'pyproject.toml': pyproject })['pyproject.toml'], 'uncovered');
    assert.equal(classify({ 'pyproject.toml': pyproject, 'uv.lock': '' })['pyproject.toml'], 'covered-by-lockfile');
  });

  it('a pyproject.toml whose dependencies cannot be ruled out is treated as declaring them', () => {
    assert.equal(classify({ 'pyproject.toml': '[project]\nname = "x"\ndynamic = ["dependencies"]\n' })['pyproject.toml'], 'uncovered');
  });

  it('setup.py and requirements/<name>.txt are scanned by nothing (verified against the pinned OSV-Scanner)', () => {
    const result = classify({ 'setup.py': '', 'requirements/base.txt': '' });
    assert.equal(result['setup.py'], 'uncovered');
    assert.equal(result['requirements/base.txt'], 'uncovered');
  });

  it('an unparseable package.json is treated as declaring dependencies', () => {
    assert.equal(classify({ 'package.json': '{ not json' })['package.json'], 'uncovered');
  });
});

describe('dependency layout: legitimately covered or empty', () => {
  it('a workspace package.json recorded in an ancestor package-lock.json is covered by it', () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'packages/ui': {}, 'node_modules/lodash': {} } });
    const result = classify({ 'package-lock.json': lock, 'package.json': PKG_WITH_DEPS, 'packages/ui/package.json': PKG_WITH_DEPS, 'packages/other/package.json': PKG_WITH_DEPS });
    assert.equal(result['packages/ui/package.json'], 'workspace');
    assert.equal(result['packages/other/package.json'], 'uncovered', 'only workspaces the lockfile records are covered');
  });

  it('manifests that declare no dependencies are not gaps', () => {
    assert.equal(classify({ 'package.json': PKG_NO_DEPS })['package.json'], 'no-dependencies');
    assert.equal(classify({ 'pyproject.toml': '[tool.black]\nline-length = 100\n' })['pyproject.toml'], 'no-dependencies');
  });

  it('a Cargo workspace member is covered by the workspace root Cargo.lock', () => {
    assert.equal(classify({ 'Cargo.lock': '', 'crates/a/Cargo.toml': '' })['crates/a/Cargo.toml'], 'covered-by-lockfile');
  });

  it('committed node_modules are not classified as the repository\'s own manifests', () => {
    const { manifests, vendored } = classifyManifests(['node_modules/x/package.json', 'package-lock.json'], () => '{}');
    assert.deepEqual(manifests.map((m) => m.path), ['package-lock.json']);
    assert.deepEqual(vendored, ['node_modules/x/package.json']);
  });
});

describe('partial dependency coverage is strictly blocking', () => {
  const manifests = classifyManifests(['svc/package-lock.json', 'setup.py', 'package-lock.json', 'go.mod', 'composer.lock', 'pnpm-lock.yaml'], () => null).manifests;

  it('every osv-only / uncovered manifest blocks; nothing in the config can unblock it', () => {
    const { blocking } = dependencyFindings(manifests);
    assert.deepEqual(blocking.map((m) => m.path).sort(), ['pnpm-lock.yaml', 'setup.py', 'svc/package-lock.json']);
    assert.equal(dependencyFindings.length, 1, 'dependencyFindings takes no acknowledgement argument');
  });

  it('covered and verified layouts do not block; unverified OSV formats warn', () => {
    const { blocking, warnings } = dependencyFindings(manifests.filter((m) => ['package-lock.json', 'go.mod', 'composer.lock'].includes(m.path)));
    assert.deepEqual(blocking, []);
    assert.ok(warnings.some((w) => /composer\.lock/.test(w)));
  });
});

describe('the effective Semgrep scope', () => {
  const files = ['src/app.py', 'tests/test_app.py', 'test/x.py', 'build/gen.py', 'vendor/lib.py', 'migrations/0001.py', 'infra/main.tf', 'README.md'];

  it("with NO .semgrepignore, Semgrep's built-in list silently drops tests/ and test/", () => {
    const scope = semgrepScope(files, { roots: ['.'], ignorePatterns: null });
    assert.equal(scope.implicit, true);
    const ignored = scope.ignored.flatMap((i) => i.sample);
    for (const path of ['tests/test_app.py', 'test/x.py', 'build/gen.py', 'vendor/lib.py']) {
      assert.ok(ignored.includes(path), `${path} should be implicitly ignored`);
    }
    assert.ok(SEMGREP_IMPLICIT_IGNORES.includes('tests/'));
  });

  it('with an explicit empty .semgrepignore, every source file is in scope', () => {
    const scope = semgrepScope(files, { roots: ['.'], ignorePatterns: [] });
    assert.equal(scope.inScope, 7);
    assert.equal(scope.ignoredTotal, 0);
  });

  it('narrowing to src/ reports everything else as outside SAST', () => {
    const scope = semgrepScope(files, { roots: ['src'], ignorePatterns: [] });
    assert.equal(scope.inScope, 1);
    assert.equal(scope.outsideRoots, 6);
    assert.ok(scope.outsideTopLevel.includes('tests/') && scope.outsideTopLevel.includes('migrations/'));
  });

  it('matches gitignore-style patterns: directories, anchoring, globs, negation', () => {
    const rules = compileIgnore(['build/', '/dist', '*.min.js', 'gen/**/*.py', '!gen/keep/**']);
    assert.equal(isIgnored('pkg/build/a.py', rules).ignored, true, 'dir pattern matches at any depth');
    assert.equal(isIgnored('build.py', rules).ignored, false, 'dir pattern does not match a file');
    assert.equal(isIgnored('dist/a.js', rules).ignored, true);
    assert.equal(isIgnored('pkg/dist/a.js', rules).ignored, false, 'leading / anchors to the root');
    assert.equal(isIgnored('web/app.min.js', rules).ignored, true);
    assert.equal(isIgnored('gen/deep/x.py', rules).ignored, true);
    assert.equal(isIgnored('gen/keep/x.py', rules).ignored, false, 'negation re-includes');
  });
});

// The scope model is checked against what the PINNED Semgrep image actually
// scanned (test/fixtures/scanner-behaviour/semgrep-scope.json, regenerated and
// compared by tools/verify-scanner-behaviour.sh).
describe('the scope model matches the pinned Semgrep image', () => {
  const fixture = JSON.parse(readFileSync('test/fixtures/scanner-behaviour/semgrep-scope.json', 'utf8'));
  for (const observation of fixture.observations) {
    it(`${observation.case}`, () => {
      const patterns =
        observation.semgrepignore === null
          ? null
          : observation.semgrepignore.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
      const { scanned } = semgrepScope(fixture.tracked, { roots: ['.'], ignorePatterns: patterns });
      assert.deepEqual(scanned, observation.scanned);
    });
  }

  it('the generated .semgrepignore introduces no hidden exclusion: with no patterns it scans exactly what an empty file scans', () => {
    const empty = fixture.observations.find((o) => o.case === 'empty .semgrepignore').scanned;
    const generated = fixture.observations.find((o) => o.case.startsWith('generated, no exclusions')).scanned;
    assert.deepEqual(generated, empty);
    for (const path of ['tests/a.py', 'test/a.py', 'migrations/a.py', 'scripts/a.py', 'infra/a.py', 'config/a.py', 'src/foo_test.py']) {
      assert.ok(generated.includes(path), `${path} must be in scope`);
    }
  });
});

describe('suggestions are shown, never applied, and never include tests or IaC', () => {
  it('suggests only generated / vendored / build directories that exist', () => {
    const suggestions = suggestIgnores(['dist/a.js', 'vendor/x.go', 'tests/t.py', 'migrations/1.py', 'terraform/main.tf', 'scripts/x.sh', 'config/app.yml', 'web/app.min.js']);
    const patterns = suggestions.map((s) => s.pattern);
    assert.deepEqual(patterns.sort(), ['*.min.js', 'dist/', 'vendor/']);
  });

  it('suggests language packs for the code that is present', () => {
    const { rulesets } = suggestRulesets(['a.py', 'b.py', 'c.ts', 'Dockerfile', 'node_modules/x/y.js']);
    assert.deepEqual(rulesets, ['p/owasp-top-ten', 'p/python', 'p/dockerfile', 'p/typescript']);
  });
});

describe('Gitleaks configuration analysis', () => {
  it('flags a config that REPLACES the default ruleset', () => {
    const analysis = analyzeGitleaksToml('title = "x"\n[[rules]]\nid = "a"\nregex = \'\'\'A[0-9]+\'\'\'\n');
    assert.equal(analysis.extendsDefault, false);
    assert.match(analysis.problems[0], /REPLACES Gitleaks' built-in ruleset/);
  });

  it('accepts [extend] useDefault = true', () => {
    const analysis = analyzeGitleaksToml('[extend]\nuseDefault = true\n\n[[rules]]\nid = "a"\n');
    assert.deepEqual(analysis.problems, []);
    assert.equal(analysis.rules, 1);
  });

  it('does not accept useDefault outside the [extend] table', () => {
    assert.equal(analyzeGitleaksToml('[[rules]]\nuseDefault = true\n').extendsDefault, false);
  });

  it('flags a broad allowlist and reports disabled built-in rules', () => {
    const analysis = analyzeGitleaksToml("[extend]\nuseDefault = true\ndisabledRules = [\"generic-api-key\"]\n[[allowlists]]\npaths = ['''.*''']\n");
    assert.ok(analysis.problems.some((p) => /broad enough/.test(p)));
    assert.ok(analysis.warnings.some((w) => /generic-api-key/.test(w)));
  });
});

describe('TruffleHog exclude-paths analysis', () => {
  const files = Array.from({ length: 40 }, (_, i) => `src/f${i}.py`).concat(['fixtures/fake.txt']);

  it('accepts a narrow, compiling exclusion and counts what it matches', () => {
    const { problems, entries } = analyzeTrufflehogExcludes('# fixtures\n^fixtures/fake\\.txt$\n', files);
    assert.deepEqual(problems, []);
    assert.deepEqual(entries, [{ pattern: '^fixtures/fake\\.txt$', matched: 1 }]);
  });

  it('refuses a catch-all or invalid regex, and warns on a broad one', () => {
    assert.ok(analyzeTrufflehogExcludes('.*\n', files).problems.length === 1);
    assert.ok(analyzeTrufflehogExcludes('(\n', files).problems.length === 1);
    assert.ok(analyzeTrufflehogExcludes('^src/\n', files).warnings.some((w) => /excludes 40 of 41/.test(w)));
  });
});
