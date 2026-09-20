// Coverage analysis: what the configured scanners will and will NOT see.
//
// Pure functions over a list of repository paths and file contents, so every
// rule here is unit-testable without a checkout. The facts they encode were
// verified against the framework's PINNED scanner images (see
// docs/onboarding-architecture.md, Part A); where a behaviour was not verified,
// the classification says so instead of claiming coverage.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';

// --- dependency manifests ------------------------------------------------------

// `osv`: OSV-Scanner (run by the framework with `scan source --recursive`) reads
// the file. `verified`: observed with the pinned OSV-Scanner v2.4.0.
// `nativeAtRoot`: the language-native scanner the framework runs, and only for
// the file at the repository root (detect-ecosystems.mjs checks the root only).
const LOCKFILES = {
  'package-lock.json': { ecosystem: 'npm', osv: true, verified: true, nativeAtRoot: 'npm audit' },
  'npm-shrinkwrap.json': { ecosystem: 'npm', osv: true, verified: false },
  'yarn.lock': { ecosystem: 'npm', osv: true, verified: true },
  'pnpm-lock.yaml': { ecosystem: 'npm', osv: true, verified: false },
  'bun.lock': { ecosystem: 'npm', osv: true, verified: false },
  'requirements.txt': { ecosystem: 'PyPI', osv: true, verified: true, nativeAtRoot: 'pip-audit' },
  'poetry.lock': { ecosystem: 'PyPI', osv: true, verified: true },
  'Pipfile.lock': { ecosystem: 'PyPI', osv: true, verified: true },
  'uv.lock': { ecosystem: 'PyPI', osv: true, verified: true },
  'pdm.lock': { ecosystem: 'PyPI', osv: true, verified: false },
  'pylock.toml': { ecosystem: 'PyPI', osv: true, verified: false },
  'go.mod': { ecosystem: 'Go', osv: true, verified: true },
  'Cargo.lock': { ecosystem: 'crates.io', osv: true, verified: true },
  'Gemfile.lock': { ecosystem: 'RubyGems', osv: true, verified: true },
  'composer.lock': { ecosystem: 'Packagist', osv: true, verified: false },
  'pom.xml': { ecosystem: 'Maven', osv: true, verified: false },
  'gradle.lockfile': { ecosystem: 'Maven', osv: true, verified: false },
  'packages.lock.json': { ecosystem: 'NuGet', osv: true, verified: false },
  'pubspec.lock': { ecosystem: 'Pub', osv: true, verified: false },
  'mix.lock': { ecosystem: 'Hex', osv: true, verified: false },
  'Package.resolved': { ecosystem: 'SwiftURL', osv: true, verified: false }
};

// Manifests that declare dependencies but are not themselves read by any
// scanner the framework runs. Covered only through a lockfile (`coveredBy`).
const MANIFESTS = {
  'package.json': { ecosystem: 'npm', coveredBy: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'] },
  'pyproject.toml': { ecosystem: 'PyPI', coveredBy: ['poetry.lock', 'uv.lock', 'pdm.lock', 'pylock.toml'] },
  'setup.py': { ecosystem: 'PyPI', coveredBy: [] },
  'setup.cfg': { ecosystem: 'PyPI', coveredBy: [] },
  Pipfile: { ecosystem: 'PyPI', coveredBy: ['Pipfile.lock'] },
  'Cargo.toml': { ecosystem: 'crates.io', coveredBy: ['Cargo.lock'], ancestorLock: true },
  Gemfile: { ecosystem: 'RubyGems', coveredBy: ['Gemfile.lock'] },
  'composer.json': { ecosystem: 'Packagist', coveredBy: ['composer.lock'] },
  'build.gradle': { ecosystem: 'Maven', coveredBy: ['gradle.lockfile'] },
  'build.gradle.kts': { ecosystem: 'Maven', coveredBy: ['gradle.lockfile'] }
};

// Ecosystems for which the framework advertises a language-native scanner. An
// npm/PyPI file that native scanner does not read is only partially covered.
const NATIVE_ECOSYSTEMS = new Set(['npm', 'PyPI']);

// Verified: OSV-Scanner reads `requirements-dev.txt` but not `requirements/base.txt`.
const isRequirementsVariant = (name) => /requirements.*\.txt$/i.test(name) && name !== 'requirements.txt';
const isRequirementsDirFile = (path) => /(^|\/)requirements\/[^/]+\.txt$/i.test(path) && !/requirements[^/]*\.txt$/i.test(posix.basename(path));

export const COVERAGE_CLASSES = {
  'native+osv': 'language-native scanner and OSV-Scanner',
  osv: 'OSV-Scanner (the framework runs no language-native scanner for this ecosystem)',
  'osv-unverified': 'OSV-Scanner documents this format; not verified against the pinned image',
  'osv-only': 'OSV-Scanner only — the framework\'s language-native scanner does NOT read this file',
  workspace: 'covered by an ancestor package-lock.json that records this workspace',
  'covered-by-lockfile': 'covered through its lockfile',
  'no-dependencies': 'declares no dependencies',
  uncovered: 'NOT SCANNED by any dependency scanner the framework runs'
};

// Classes that block generation. Nothing in the config can unblock them.
export const BLOCKING_CLASSES = new Set(['osv-only', 'uncovered']);

function hasEntries(value) {
  return value && typeof value === 'object' && Object.keys(value).length > 0;
}

function packageJsonDeclaresDependencies(text) {
  try {
    const json = JSON.parse(text);
    return ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies']
      .some((key) => (Array.isArray(json[key]) ? json[key].length > 0 : hasEntries(json[key])));
  } catch {
    return null; // unparseable: unknown, treated as declaring dependencies
  }
}

// A deliberately small reader: does this pyproject.toml declare any runtime or
// development dependency? `null` means "cannot tell" and is treated as yes.
function pyprojectDeclaresDependencies(text) {
  const tables = new Map();
  let current = '';
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/#.*$/, '').trim();
    const header = /^\[\[?([^\]]+)\]\]?$/.exec(line);
    if (header) {
      current = header[1].trim();
      tables.set(current, tables.get(current) ?? []);
      continue;
    }
    if (line) {
      tables.set(current, [...(tables.get(current) ?? []), line]);
    }
  }
  const body = (name) => (tables.get(name) ?? []).join('\n');
  const project = body('project');
  const listAssignment = /(^|\n)\s*dependencies\s*=\s*\[([\s\S]*?)\]/.exec(project);
  if (/(^|\n)\s*dependencies\s*=/.test(project) && !listAssignment) {
    return null;
  }
  if (listAssignment && /["']/.test(listAssignment[2])) {
    return true;
  }
  if (/(^|\n)\s*dynamic\s*=\s*\[[^\]]*["']dependencies["']/.test(project)) {
    return null;
  }
  for (const name of tables.keys()) {
    if (name === 'project.optional-dependencies' || name === 'dependency-groups') {
      if (/=\s*\[[^\]]*["']/.test(body(name)) || /=\s*\[\s*$/m.test(body(name))) {
        return true;
      }
    }
    if (/^tool\.poetry\.(?:dev-)?dependencies$|^tool\.poetry\.group\.[^.]+\.dependencies$/.test(name)) {
      const entries = (tables.get(name) ?? []).filter((line) => !/^python\s*=/.test(line));
      if (entries.length > 0) {
        return true;
      }
    }
    if (/^tool\.pdm\.dev-dependencies$|^tool\.uv$/.test(name) && /dev-dependencies\s*=|=\s*\[/.test(body(name))) {
      return true;
    }
  }
  return false;
}

function lockfileWorkspaces(text) {
  try {
    const json = JSON.parse(text);
    return new Set(Object.keys(json.packages ?? {}).filter((key) => key && !key.includes('node_modules/')));
  } catch {
    return new Set();
  }
}

// files: every tracked path (posix, relative). readText(path) -> string|null.
export function classifyManifests(files, readText) {
  const fileSet = new Set(files);
  const results = [];
  const skippedVendored = [];
  const workspaceIndex = new Map();
  for (const file of files) {
    if (posix.basename(file) === 'package-lock.json' && !/(^|\/)node_modules\//.test(file)) {
      const dir = posix.dirname(file);
      const workspaces = lockfileWorkspaces(readText(file) ?? '');
      workspaceIndex.set(dir === '.' ? '' : dir, workspaces);
    }
  }
  for (const file of [...files].sort()) {
    if (/(^|\/)node_modules\//.test(file)) {
      if (posix.basename(file) === 'package.json' && !/node_modules\/.*node_modules\//.test(file)) {
        skippedVendored.push(file);
      }
      continue;
    }
    const name = posix.basename(file);
    const dir = posix.dirname(file);
    const atRoot = dir === '.';
    let entry = null;

    if (LOCKFILES[name] || isRequirementsVariant(name)) {
      const spec = LOCKFILES[name] ?? { ecosystem: 'PyPI', osv: true, verified: true };
      const native = atRoot && spec.nativeAtRoot ? spec.nativeAtRoot : null;
      let coverage;
      if (native) {
        coverage = 'native+osv';
      } else if (NATIVE_ECOSYSTEMS.has(spec.ecosystem)) {
        coverage = 'osv-only';
      } else {
        coverage = spec.verified ? 'osv' : 'osv-unverified';
      }
      const why = [];
      if (coverage === 'osv-only') {
        if (LOCKFILES[name]?.nativeAtRoot) {
          why.push(`${LOCKFILES[name].nativeAtRoot} runs only on the repository-root ${name}`);
        } else {
          why.push(`the framework runs no ${spec.ecosystem === 'npm' ? 'npm audit' : 'pip-audit'} for ${name}`);
        }
        if (!spec.verified) {
          why.push('OSV-Scanner support for this format was not verified against the pinned image');
        }
      }
      entry = { path: file, ecosystem: spec.ecosystem, kind: 'lockfile', coverage, native, why };
    } else if (isRequirementsDirFile(file)) {
      entry = {
        path: file,
        ecosystem: 'PyPI',
        kind: 'manifest',
        coverage: 'uncovered',
        native: null,
        why: ['OSV-Scanner does not read requirements/<name>.txt (verified), and pip-audit reads only the root requirements.txt']
      };
    } else if (MANIFESTS[name]) {
      const spec = MANIFESTS[name];
      const sibling = spec.coveredBy.find((lock) => fileSet.has(atRoot ? lock : `${dir}/${lock}`));
      let coverage = 'uncovered';
      const why = [];
      if (sibling) {
        coverage = 'covered-by-lockfile';
        why.push(`covered through ${atRoot ? sibling : `${dir}/${sibling}`}`);
      } else if (spec.ancestorLock) {
        let cursor = dir;
        while (cursor !== '.' && cursor !== '') {
          cursor = posix.dirname(cursor);
          const candidate = cursor === '.' ? spec.coveredBy[0] : `${cursor}/${spec.coveredBy[0]}`;
          if (fileSet.has(candidate)) {
            coverage = 'covered-by-lockfile';
            why.push(`covered through ${candidate}`);
            break;
          }
        }
      }
      if (coverage === 'uncovered' && name === 'package.json') {
        for (const [lockDir, workspaces] of workspaceIndex) {
          const relative = lockDir === '' ? dir : dir.startsWith(`${lockDir}/`) ? dir.slice(lockDir.length + 1) : null;
          if (relative && relative !== '.' && workspaces.has(relative)) {
            coverage = 'workspace';
            why.push(`recorded as workspace "${relative}" in ${lockDir ? `${lockDir}/` : ''}package-lock.json`);
            break;
          }
        }
      }
      if (coverage === 'uncovered') {
        const text = readText(file);
        const declares =
          name === 'package.json'
            ? packageJsonDeclaresDependencies(text ?? '')
            : name === 'pyproject.toml'
              ? pyprojectDeclaresDependencies(text ?? '')
              : null;
        if (declares === false) {
          coverage = 'no-dependencies';
        } else {
          why.push(
            `no lockfile (${spec.coveredBy.join(', ') || 'none exists for this format'}) next to it; OSV-Scanner reads lockfiles, not ${name}` +
              (declares === null ? ' (dependencies could not be ruled out)' : '')
          );
        }
      }
      entry = { path: file, ecosystem: spec.ecosystem, kind: 'manifest', coverage, native: null, why };
    }
    if (entry) {
      results.push(entry);
    }
  }
  return { manifests: results, vendored: skippedVendored };
}

// Splits classified manifests into BLOCKING gaps and warnings. There is no
// local override: a gap that onboarding accepted but CI never re-checks would
// keep the security gate green long after the decision should have expired. A
// future runtime, conformance-backed exception is designed in
// docs/onboarding-architecture.md B.6; it does not exist yet.
export function dependencyFindings(manifests) {
  const blocking = manifests.filter((manifest) => BLOCKING_CLASSES.has(manifest.coverage));
  const warnings = manifests
    .filter((manifest) => manifest.coverage === 'osv-unverified')
    .map((manifest) => `${manifest.path}: ${COVERAGE_CLASSES['osv-unverified']}`);
  return { blocking, warnings };
}

// --- gitignore-style matching (for the .semgrepignore / scope preview) ----------

function globToRegExp(glob) {
  let out = '';
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === '*') {
      if (glob[index + 1] === '*') {
        index += 1;
        if (glob[index + 1] === '/') {
          index += 1;
          out += '(?:.*/)?';
        } else {
          out += '.*';
        }
      } else {
        out += '[^/]*';
      }
    } else if (char === '?') {
      out += '[^/]';
    } else if (char === '[') {
      const end = glob.indexOf(']', index + 1);
      if (end === -1) {
        out += '\\[';
      } else {
        out += `[${glob.slice(index + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\')}]`;
        index = end;
      }
    } else if (char === '\\' && index + 1 < glob.length) {
      index += 1;
      out += glob[index].replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    } else {
      out += char.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
    }
  }
  return out;
}

export function compileIgnore(patterns) {
  return patterns
    .map((raw) => raw.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      let pattern = line;
      const negated = pattern.startsWith('!');
      if (negated) {
        pattern = pattern.slice(1);
      }
      const directoryOnly = pattern.endsWith('/');
      pattern = pattern.replace(/\/+$/, '');
      const anchored = pattern.startsWith('/') || pattern.includes('/');
      pattern = pattern.replace(/^\//, '');
      const body = globToRegExp(pattern);
      const regex = new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}$`);
      return { source: line, negated, directoryOnly, regex };
    });
}

// A path is ignored when the last matching rule (for the file itself or any of
// its parent directories) is not a negation.
export function isIgnored(path, rules) {
  const parts = path.split('/');
  const candidates = [];
  for (let index = 1; index < parts.length; index += 1) {
    candidates.push({ path: parts.slice(0, index).join('/'), directory: true });
  }
  candidates.push({ path, directory: false });
  let ignored = false;
  let matchedBy = null;
  for (const candidate of candidates) {
    for (const rule of rules) {
      if (rule.directoryOnly && !candidate.directory) {
        continue;
      }
      if (rule.regex.test(candidate.path)) {
        ignored = !rule.negated;
        matchedBy = rule.negated ? null : rule.source;
      }
    }
    if (ignored && candidate.directory) {
      return { ignored, matchedBy };
    }
  }
  return { ignored, matchedBy };
}

// Semgrep's built-in ignore list, used ONLY when no .semgrepignore exists
// (verified with the pinned Semgrep 1.176.0: tests/, test/, build/, vendor/ and
// node_modules/ were skipped with no file present).
export const SEMGREP_IMPLICIT_IGNORES = [
  'node_modules/', 'build/', 'dist/', 'vendor/', '.env/', '.venv/', '.tox/', '*.min.js', '.npm/', '.yarn/',
  'test/', 'tests/', '*_test.go', '.semgrep', '.semgrep_logs/'
];

const SOURCE_EXTENSIONS = /\.(?:py|js|mjs|cjs|jsx|ts|tsx|go|java|kt|kts|rb|php|cs|rs|scala|c|h|cc|cpp|hpp|swift|sh|bash|tf|hcl|ya?ml|json|tpl|html|vue|svelte|ex|exs|lua|sol|dockerfile)$|(^|\/)Dockerfile[^/]*$/i;

export function isSourceLike(path) {
  return SOURCE_EXTENSIONS.test(path);
}

function underRoot(path, root) {
  return root === '.' || path === root || path.startsWith(`${root}/`);
}

// The effective SAST scope: roots, then ignore rules. `ignorePatterns === null`
// means "no .semgrepignore file" and applies Semgrep's implicit list.
export function semgrepScope(files, { roots, ignorePatterns }) {
  const implicit = ignorePatterns === null;
  const rules = compileIgnore(implicit ? SEMGREP_IMPLICIT_IGNORES : ignorePatterns);
  const inScope = [];
  const outsideRoots = [];
  const ignored = new Map();
  for (const file of files) {
    if (!isSourceLike(file)) {
      continue;
    }
    if (!roots.some((root) => underRoot(file, root))) {
      outsideRoots.push(file);
      continue;
    }
    const verdict = isIgnored(file, rules);
    if (verdict.ignored) {
      ignored.set(verdict.matchedBy, [...(ignored.get(verdict.matchedBy) ?? []), file]);
    } else {
      inScope.push(file);
    }
  }
  const outsideTopLevel = [...new Set(outsideRoots.map((file) => (file.includes('/') ? `${file.split('/')[0]}/` : file)))].sort();
  return {
    implicit,
    scanned: inScope.sort(),
    inScope: inScope.length,
    ignored: [...ignored.entries()].map(([pattern, matched]) => ({ pattern, count: matched.length, sample: matched.slice(0, 3) })),
    ignoredTotal: [...ignored.values()].reduce((sum, list) => sum + list.length, 0),
    outsideRoots: outsideRoots.length,
    outsideTopLevel
  };
}

// Directories that are generated, vendored or build output. Suggested for
// exclusion ONLY when present, and only after being shown to the owner. Tests,
// migrations, infrastructure-as-code, scripts and configuration are never here.
const SUGGESTABLE_DIRECTORIES = ['node_modules', 'vendor', 'third_party', 'dist', 'build', 'out', 'target', '.venv', 'venv', 'coverage', '.next', '.nuxt', '__generated__', 'generated'];
const SUGGESTABLE_GLOBS = ['*.min.js', '*.min.css', '*.pb.go', '*_pb2.py', '*_pb2_grpc.py', '*.generated.*'];

export function suggestIgnores(files) {
  const suggestions = [];
  for (const dir of SUGGESTABLE_DIRECTORIES) {
    const matched = files.filter((file) => file.split('/').slice(0, -1).includes(dir));
    if (matched.length > 0) {
      suggestions.push({ pattern: `${dir}/`, count: matched.length, reason: 'generated, vendored or build output' });
    }
  }
  for (const glob of SUGGESTABLE_GLOBS) {
    const [rule] = compileIgnore([glob]);
    const matched = files.filter((file) => rule.regex.test(file));
    if (matched.length > 0) {
      suggestions.push({ pattern: glob, count: matched.length, reason: 'generated or minified file' });
    }
  }
  return suggestions;
}

// --- languages -> suggested Semgrep packs ---------------------------------------

const LANGUAGE_PACKS = [
  { pack: 'p/python', test: /\.py$/ },
  { pack: 'p/javascript', test: /\.(?:js|mjs|cjs|jsx)$/ },
  { pack: 'p/typescript', test: /\.(?:ts|tsx)$/ },
  { pack: 'p/golang', test: /\.go$/ },
  { pack: 'p/java', test: /\.java$/ },
  { pack: 'p/kotlin', test: /\.kts?$/ },
  { pack: 'p/ruby', test: /\.rb$/ },
  { pack: 'p/php', test: /\.php$/ },
  { pack: 'p/csharp', test: /\.cs$/ },
  { pack: 'p/rust', test: /\.rs$/ },
  { pack: 'p/scala', test: /\.scala$/ },
  { pack: 'p/terraform', test: /\.tf$/ },
  { pack: 'p/dockerfile', test: /(^|\/)Dockerfile[^/]*$|\.dockerfile$/i }
];

export function suggestRulesets(files) {
  const counts = LANGUAGE_PACKS.map(({ pack, test }) => ({
    pack,
    count: files.filter((file) => !/(^|\/)(node_modules|vendor|third_party)\//.test(file) && test.test(file)).length
  })).filter((entry) => entry.count > 0);
  counts.sort((a, b) => b.count - a.count || a.pack.localeCompare(b.pack));
  return { rulesets: ['p/owasp-top-ten', ...counts.map((entry) => entry.pack)], languages: counts };
}

// --- Gitleaks configuration --------------------------------------------------------

// Verified with the pinned Gitleaks v8.30.1: a config with rules but WITHOUT
// `[extend] useDefault = true` found 0 of 2 secrets the default ruleset found.
export function analyzeGitleaksToml(text) {
  const lines = text.split('\n');
  let table = '';
  let extendsDefault = false;
  let extendsPath = null;
  const disabledRules = [];
  const allowlistValues = [];
  let rules = 0;
  for (const raw of lines) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    const header = /^\[\[?\s*([^\]]+?)\s*\]\]?$/.exec(line);
    if (header) {
      table = header[1];
      if (table === 'rules') {
        rules += 1;
      }
      continue;
    }
    if (table === 'extend') {
      if (/^useDefault\s*=\s*true\b/.test(line)) {
        extendsDefault = true;
      }
      const path = /^path\s*=\s*["'](.+)["']/.exec(line);
      if (path) {
        extendsPath = path[1];
      }
      const disabled = /^disabledRules\s*=\s*\[(.*)\]/.exec(line);
      if (disabled) {
        disabledRules.push(...[...disabled[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1]));
      }
    }
    if (/^(allowlist|allowlists|rules\.allowlist|rules\.allowlists)$/.test(table)) {
      const values = /^(paths|regexes|stopwords|commits)\s*=\s*\[(.*)\]?/.exec(line);
      if (values) {
        allowlistValues.push(...[...values[2].matchAll(/'''(.*?)'''|"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => ({ kind: values[1], value: m[1] ?? m[2] ?? m[3] })));
      }
    }
  }
  const problems = [];
  const warnings = [];
  if (!extendsDefault) {
    problems.push(
      extendsPath
        ? `extends "${extendsPath}" instead of the built-in ruleset; ssd-onboard cannot verify the default rules are preserved. Use [extend] useDefault = true`
        : 'has no [extend] useDefault = true, so it REPLACES Gitleaks\' built-in ruleset (verified: pinned v8.30.1 found 0 of 2 default-rule secrets with a rules-only config)'
    );
  }
  if (disabledRules.length > 0) {
    warnings.push(`disables built-in rules: ${disabledRules.join(', ')}`);
  }
  for (const { kind, value } of allowlistValues) {
    if (kind === 'paths' || kind === 'regexes') {
      const trimmed = value.trim();
      let broad = ['.*', '.+', '^.*$', '.', '(.*)', '*', '**', '/'].includes(trimmed);
      if (!broad) {
        try {
          broad = new RegExp(trimmed).test('') || new RegExp(trimmed).test('src/app.py');
        } catch {
          warnings.push(`allowlist ${kind} entry '${value}' does not compile as a JavaScript regex; review it by hand`);
        }
      }
      if (broad) {
        problems.push(`allowlist ${kind} entry '${value}' is broad enough to suppress findings across the repository`);
      }
    }
  }
  if (allowlistValues.length > 0 && problems.length === 0) {
    warnings.push(`carries ${allowlistValues.length} allowlist entr${allowlistValues.length === 1 ? 'y' : 'ies'}; each suppresses secret findings and should be reviewed`);
  }
  return { extendsDefault, extendsPath, disabledRules, rules, problems, warnings };
}

// --- TruffleHog exclude-paths ---------------------------------------------------------

export function analyzeTrufflehogExcludes(text, files) {
  const problems = [];
  const warnings = [];
  const entries = [];
  for (const [index, raw] of text.split('\n').entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    let regex;
    try {
      regex = new RegExp(line);
    } catch (error) {
      problems.push(`line ${index + 1}: '${line}' is not a valid regular expression (${error.message})`);
      continue;
    }
    if (regex.test('') || ['.*', '.+', '^.*$', '.'].includes(line)) {
      problems.push(`line ${index + 1}: '${line}' matches every path, which disables the TruffleHog scan`);
      continue;
    }
    const matched = files.filter((file) => regex.test(file));
    entries.push({ pattern: line, matched: matched.length });
    if (files.length >= 20 && matched.length / files.length > 0.25) {
      warnings.push(`line ${index + 1}: '${line}' excludes ${matched.length} of ${files.length} tracked files from secret scanning`);
    }
    if (matched.length === 0) {
      warnings.push(`line ${index + 1}: '${line}' matches no tracked file today`);
    }
  }
  return { entries, problems, warnings };
}

// --- scope digest --------------------------------------------------------------------

// Recorded when a baseline is accepted. A later change to rulesets, roots or
// ignore patterns changes what Semgrep reports, which the baseline never saw.
export function semgrepScopeDigest({ rulesets, roots, ignorePatterns }) {
  const canonical = JSON.stringify({
    rulesets: [...rulesets].sort(),
    roots: [...roots].sort(),
    ignore: ignorePatterns === null ? null : [...ignorePatterns]
  });
  return createHash('sha256').update(canonical).digest('hex');
}
