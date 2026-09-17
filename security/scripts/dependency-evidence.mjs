// Normalized dependency evidence: what the scanner reports and the repository's
// own manifests PROVE about a vulnerable package, kept apart from what they only
// suggest. Documented in docs/evidence-model.md; that document is the contract.
//
// Four facts that are easy to conflate are kept separate here:
//
//   advisory match   a scanner says an advisory applies to a package@version
//                    (the raw finding; policy decides on it, not on this file)
//   relationship     how the package is in the tree: direct | transitive | unknown
//   resolution       which version is actually in effect, and whether the
//                    evidence agrees: consistent | conflicting | unknown
//   policy action    BLOCK / EXCEPTION / LOG, decided by the gate elsewhere
//
// Nothing in this file is read by a policy decision. It is PRESENTATION and
// BENCHMARKING evidence only: every function here fails toward "unknown" and
// never throws into the gate.
//
// What it will not do: fetch registry metadata, resolve dependencies, or infer
// ancestry. A package missing from the root manifest is NOT thereby transitive —
// the manifest may be incomplete, include other files, or the scanner may be
// wrong. Relationship is `transitive` only when a report carries an explicit
// dependency path.
import { readFile } from 'node:fs/promises';
import { basename, isAbsolute, relative, resolve, sep } from 'node:path';

export const EVIDENCE_SCHEMA_VERSION = 1;

// How strongly a version observation's provenance establishes the version in
// effect. Deterministic; see docs/evidence-model.md "Resolution confidence".
//   high    the version is written down by the project or observed in use
//   medium  a scanner resolved it from an unlocked manifest
//   low     a scanner reported it without stating how it was derived
export const PROVENANCE_STRENGTH = {
  'manifest-declared': 'high',
  'lockfile-resolved': 'high',
  'environment-observed': 'high',
  'scanner-resolved': 'medium',
  'scanner-inferred': 'low',
  unknown: 'low'
};
const CONFIDENCE_RANK = { high: 0, medium: 1, low: 2 };

// Files whose contents ARE a resolution: a version read from one of these was
// chosen by the project's resolver and written down, not guessed by a scanner.
const LOCKFILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'poetry.lock',
  'Pipfile.lock',
  'pdm.lock',
  'uv.lock',
  'pylock.toml',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'go.sum',
  'gradle.lockfile',
  'packages.lock.json',
  'pubspec.lock',
  'mix.lock',
  'conan.lock',
  'renv.lock'
]);

// _source-security.yml mounts the consumer checkout at /repo for OSV-Scanner, so
// its source paths arrive as /repo/<path>.
const SCANNER_MOUNT = '/repo/';

const REQUIREMENTS_FILE = /requirements.*\.txt$/i;

// PEP 503: PyPI names compare case-insensitively with runs of -, _ and . equal.
// Every other ecosystem is compared exactly: guessing a normalization rule for
// an ecosystem would risk merging two genuinely different packages.
export function normalizePackageName(ecosystem, name) {
  return ecosystem === 'PyPI' ? String(name).toLowerCase().replace(/[-_.]+/g, '-') : String(name);
}

// Version equality for "do these observations agree". PyPI release numbers
// compare per PEP 440 (3.9 == 3.9.0, leading zeros ignored); anything else, and
// any non-numeric PyPI version, compares as an exact (case-folded for PyPI)
// string. Never treats two different strings as equal on a guess.
export function versionKey(ecosystem, version) {
  const text = String(version).trim();
  if (ecosystem !== 'PyPI') {
    return text;
  }
  const lowered = text.toLowerCase().replace(/^v/, '');
  if (!/^\d+(\.\d+)*$/.test(lowered)) {
    return lowered;
  }
  const parts = lowered.split('.').map(Number);
  while (parts.length > 1 && parts.at(-1) === 0) {
    parts.pop();
  }
  return parts.join('.');
}

function unique(values) {
  return [...new Set(values)];
}

function advisoryIdentifiers(record) {
  const ids = [record?.id, ...(Array.isArray(record?.aliases) ? record.aliases : [])];
  return ids.filter((id) => typeof id === 'string' && id.trim() !== '').map((id) => id.trim());
}

// A scanner-reported path as a repository-relative path, or null when it does
// not point inside the checkout (then it is shown, never read).
function repositoryPath(rawPath, repoRoot) {
  if (typeof rawPath !== 'string' || rawPath === '') {
    return null;
  }
  let candidate = rawPath;
  if (candidate.startsWith(SCANNER_MOUNT)) {
    candidate = candidate.slice(SCANNER_MOUNT.length);
  }
  const absolute = isAbsolute(candidate) ? candidate : resolve(repoRoot, candidate);
  const rel = relative(repoRoot, absolute);
  if (rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    return null;
  }
  return rel.split(sep).join('/');
}

// Declarations in a pip requirements file. Deliberately a READER, not a
// resolver: it records what each line literally declares. Includes (-r/-c),
// editable installs, URLs and local paths are listed as unparsed rather than
// followed, so a package declared only through them stays undeclared here.
export function parseRequirements(text) {
  const declarations = [];
  const unparsed = [];
  let buffer = '';
  let startLine = 0;

  text.split(/\r?\n/).forEach((rawLine, index) => {
    if (buffer === '') {
      startLine = index + 1;
    }
    if (/\\\s*$/.test(rawLine)) {
      buffer += `${rawLine.replace(/\\\s*$/, '')} `;
      return;
    }
    const logical = `${buffer}${rawLine}`;
    buffer = '';
    const content = logical.replace(/(^|\s)#.*$/, '').trim();
    if (content === '') {
      return;
    }
    if (content.startsWith('-') || /:\/\//.test(content) || /^[.~/]/.test(content)) {
      unparsed.push({ line: startLine, text: content });
      return;
    }
    const requirement = content.split(';')[0].replace(/\s--hash=\S+/g, '').trim();
    const match = requirement.match(/^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/);
    if (!match) {
      unparsed.push({ line: startLine, text: content });
      return;
    }
    const [, name, extras = '', rawSpecifier] = match;
    const specifier = rawSpecifier.replace(/\s+/g, '');
    const exact = specifier.match(/^===?([^,*@]+)$/);
    declarations.push({
      package: name,
      requirement: `${name}${extras.replace(/\s+/g, '')}${specifier}`,
      exactVersion: exact ? exact[1] : null,
      line: startLine
    });
  });

  return { declarations, unparsed };
}

async function readManifest(path, repoRoot) {
  const manifest = { path, ecosystem: 'PyPI', format: 'requirements.txt' };
  let text;
  try {
    text = await readFile(resolve(repoRoot, path), 'utf8');
  } catch (error) {
    return { ...manifest, status: error?.code === 'ENOENT' ? 'missing' : 'unreadable', declarations: [] };
  }
  const { declarations, unparsed } = parseRequirements(text);
  return { ...manifest, status: 'parsed', declarations, ...(unparsed.length > 0 ? { unparsed } : {}) };
}

function addObservation(observations, observation) {
  const key = [
    observation.scanner,
    observation.ecosystem,
    normalizePackageName(observation.ecosystem, observation.package),
    observation.version,
    observation.provenance,
    observation.source
  ].join('\0');
  const existing = observations.get(key);
  if (existing) {
    existing.advisoryIds = unique([...existing.advisoryIds, ...observation.advisoryIds]);
    return;
  }
  observations.set(key, observation);
}

// The run-level record written to security-gate.json as `dependencyEvidence`.
// Inputs are the already-parsed scanner reports the gate evaluated, so evidence
// and policy can never be built from different data.
//
//   pipAuditSource  the requirements file pip-audit audited (the workflow runs
//                   `pip-audit --requirement requirements.txt`); pip-audit's
//                   JSON does not name it
export async function collectDependencyEvidence({ repoDir = '.', pipAudit = null, pipAuditSource = null, osv = null } = {}) {
  const repoRoot = resolve(repoDir);
  const observations = new Map();

  if (pipAudit && Array.isArray(pipAudit.dependencies)) {
    const source = repositoryPath(pipAuditSource, repoRoot) ?? (typeof pipAuditSource === 'string' ? pipAuditSource : null);
    for (const dependency of pipAudit.dependencies) {
      if (typeof dependency?.name !== 'string' || dependency.name === '') {
        continue;
      }
      const version = typeof dependency.version === 'string' && dependency.version !== '' ? dependency.version : null;
      addObservation(observations, {
        scanner: 'pip-audit',
        ecosystem: 'PyPI',
        package: dependency.name,
        version,
        // pip-audit reports the version it audited for the requirements file;
        // its JSON does not say whether that came from the file or a resolve.
        provenance: version ? 'scanner-resolved' : 'unknown',
        source,
        advisoryIds: unique((Array.isArray(dependency.vulns) ? dependency.vulns : []).flatMap(advisoryIdentifiers))
      });
    }
  }

  for (const result of Array.isArray(osv?.results) ? osv.results : []) {
    const rawSource = result?.source?.path;
    const source = repositoryPath(rawSource, repoRoot) ?? (typeof rawSource === 'string' && rawSource !== '' ? rawSource : null);
    for (const entry of Array.isArray(result?.packages) ? result.packages : []) {
      const pkg = entry?.package;
      if (typeof pkg?.name !== 'string' || typeof pkg?.ecosystem !== 'string' || pkg.ecosystem === '') {
        continue;
      }
      const version = typeof pkg.version === 'string' && pkg.version !== '' ? pkg.version : null;
      addObservation(observations, {
        scanner: 'osv-scanner',
        ecosystem: pkg.ecosystem,
        package: pkg.name,
        version,
        // A lockfile is a recorded resolution. For any other source OSV-Scanner's
        // report does not state how it derived the version.
        provenance: !version ? 'unknown' : source && LOCKFILES.has(basename(source)) ? 'lockfile-resolved' : 'scanner-inferred',
        source,
        advisoryIds: unique((Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities : []).flatMap(advisoryIdentifiers))
      });
    }
  }

  const manifestPaths = unique(
    [...observations.values()]
      .map((observation) => observation.source)
      .filter((source) => typeof source === 'string' && REQUIREMENTS_FILE.test(basename(source)))
      .filter((source) => repositoryPath(source, repoRoot) === source)
  ).sort();
  const manifests = await Promise.all(manifestPaths.map((path) => readManifest(path, repoRoot)));

  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    manifests,
    observations: [...observations.values()]
  };
}

// Never lets evidence collection affect the gate: any failure yields a record
// that says evidence is unavailable, and per-issue evidence falls back to what
// the raw findings themselves carry.
export async function collectDependencyEvidenceSafely(options) {
  try {
    return await collectDependencyEvidence(options);
  } catch (error) {
    return { schemaVersion: EVIDENCE_SCHEMA_VERSION, unavailable: `dependency evidence could not be collected: ${error?.message ?? error}` };
  }
}

// Observations derived from the raw findings alone, for a gate result written
// before `dependencyEvidence` existed. Source and provenance are unknown.
function observationsFromFindings(members, ecosystem) {
  const observations = new Map();
  for (const finding of members) {
    const version = typeof finding.installedVersion === 'string' && finding.installedVersion !== '' ? finding.installedVersion : null;
    addObservation(observations, {
      scanner: finding.source,
      ecosystem,
      package: finding.package,
      version,
      provenance: version && finding.source === 'pip-audit' ? 'scanner-resolved' : 'unknown',
      source: null,
      advisoryIds: advisoryIdentifiers(finding)
    });
  }
  return [...observations.values()];
}

function validPaths(observation, ecosystem, key) {
  if (!Array.isArray(observation.dependencyPaths)) {
    return [];
  }
  return observation.dependencyPaths.filter(
    (path) =>
      Array.isArray(path) &&
      path.length >= 2 &&
      path.every((name) => typeof name === 'string' && name !== '') &&
      normalizePackageName(ecosystem, path.at(-1)) === key
  );
}

// The per-issue evidence object attached to a correlated dependency issue.
// `issue` needs { package, ecosystem, advisoryIds }; `members` are its raw
// findings; `record` is the run-level `dependencyEvidence` (or null).
export function issueDependencyEvidence(issue, members, record) {
  const { package: pkg, ecosystem } = issue;
  const key = normalizePackageName(ecosystem, pkg);
  const issueIds = new Set((issue.advisoryIds ?? []).map((id) => id.toUpperCase()));
  const samePackage = (entry) => entry.ecosystem === ecosystem && normalizePackageName(ecosystem, entry.package) === key;

  const scannerObservations =
    record && Array.isArray(record.observations)
      ? record.observations.filter(samePackage)
      : observationsFromFindings(members, ecosystem);

  // Manifests count only when a scanner analyzed them while reporting THIS
  // package; a declaration elsewhere in the repository proves nothing here.
  const sources = unique(scannerObservations.map((observation) => observation.source).filter((source) => typeof source === 'string'));
  const manifests = (record && Array.isArray(record.manifests) ? record.manifests : []).filter(
    (manifest) => manifest.status === 'parsed' && manifest.ecosystem === ecosystem && sources.includes(manifest.path)
  );
  const declarations = manifests.flatMap((manifest) =>
    manifest.declarations
      .filter((declaration) => normalizePackageName(ecosystem, declaration.package) === key)
      .map((declaration) => ({
        manifest: manifest.path,
        requirement: declaration.requirement,
        exactVersion: declaration.exactVersion,
        line: declaration.line
      }))
  );
  const dependencyPaths = scannerObservations.flatMap((observation) =>
    validPaths(observation, ecosystem, key).map((path) => ({ path, scanner: observation.scanner, source: observation.source }))
  );

  let relationship;
  if (declarations.length > 0) {
    relationship = { value: 'direct', basis: 'manifest-declaration' };
  } else if (dependencyPaths.length > 0) {
    relationship = { value: 'transitive', basis: 'scanner-dependency-path' };
  } else {
    relationship = { value: 'unknown', basis: 'none' };
  }

  const observations = [
    ...declarations
      .filter((declaration) => declaration.exactVersion !== null)
      .map((declaration) => ({
        scanner: null,
        version: declaration.exactVersion,
        provenance: 'manifest-declared',
        source: declaration.manifest,
        advisoryReported: null
      })),
    ...scannerObservations.map((observation) => ({
      scanner: observation.scanner,
      version: observation.version,
      provenance: observation.provenance,
      source: observation.source,
      advisoryReported: observation.advisoryIds.some((id) => issueIds.has(id.toUpperCase()))
    }))
  ];

  const versioned = observations.filter((observation) => observation.version !== null);
  const distinct = new Map();
  for (const observation of versioned) {
    const versionId = versionKey(ecosystem, observation.version);
    if (!distinct.has(versionId)) {
      distinct.set(versionId, observation.version);
    }
  }

  let status;
  let confidence;
  if (distinct.size === 0) {
    status = 'unknown';
    confidence = 'low';
  } else if (distinct.size === 1) {
    status = 'consistent';
    confidence = versioned
      .map((observation) => PROVENANCE_STRENGTH[observation.provenance] ?? 'low')
      .sort((a, b) => CONFIDENCE_RANK[a] - CONFIDENCE_RANK[b])[0];
  } else {
    // Two observations disagree: no strength ranking picks a winner. The
    // manifest is not silently preferred over a scanner, nor the reverse.
    status = 'conflicting';
    confidence = 'conflicting';
  }

  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    package: pkg,
    ecosystem,
    relationship: {
      ...relationship,
      declarations,
      dependencyPaths,
      manifestsChecked: manifests.map((manifest) => manifest.path)
    },
    resolution: {
      status,
      confidence,
      version: status === 'consistent' ? [...distinct.values()][0] : null,
      versions: [...distinct.values()],
      observations
    },
    ...(record?.unavailable ? { unavailable: record.unavailable } : {})
  };
}

// The evidence builder must never break correlation or the gate. On any error
// the issue carries an explicit "unknown" rather than nothing.
export function issueDependencyEvidenceSafely(issue, members, record) {
  try {
    return issueDependencyEvidence(issue, members, record);
  } catch (error) {
    return {
      schemaVersion: EVIDENCE_SCHEMA_VERSION,
      package: issue.package,
      ecosystem: issue.ecosystem,
      relationship: { value: 'unknown', basis: 'none', declarations: [], dependencyPaths: [], manifestsChecked: [] },
      resolution: { status: 'unknown', confidence: 'low', version: null, versions: [], observations: [] },
      unavailable: `dependency evidence could not be built: ${error?.message ?? error}`
    };
  }
}
