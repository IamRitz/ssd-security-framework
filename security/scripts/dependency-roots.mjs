// npm dependency roots: the directories in which the framework runs `npm audit`.
//
// ONE implementation, three readers. The dependency-scanning job decides where to
// run npm audit from it (npm-audit-roots.mjs), the source gate re-derives it from
// its own checkout to decide which npm audit reports it REQUIRES
// (security-gate.mjs), and ssd-onboard classifies npm lockfiles from it
// (onboarding/lib/coverage.mjs). Because all three call the same function over
// the same tracked files, onboarding can only say `native+osv` for a lockfile
// that CI really audits, and CI cannot quietly audit fewer roots than the gate
// expects.
//
// A dependency root is a repository-relative directory holding a TRACKED
// `package-lock.json` or `npm-shrinkwrap.json`, outside any `node_modules/`.
// When a directory holds both, npm reads the shrinkwrap and ignores the
// package-lock (verified with npm 10), so the shrinkwrap is the root's lockfile
// and the package-lock is reported as `shadowed`.
//
// TRACKED, not present: the list comes from `git ls-files --cached`, because a
// CI checkout contains exactly the tracked files. An ignored or untracked
// lockfile on a developer's disk is scanned by nothing in CI and must never
// read as coverage. Outside a git work tree (unit fixtures) a filesystem walk is
// the fallback; it skips `.git` and `node_modules` and follows no symbolic link.
//
// UNTRUSTED INPUT: every path here comes from the repository and ends up as the
// working directory of a process. A path is refused (`rejected`, never silently
// dropped) when it is absolute, contains an empty, '.' or '..' segment, a
// backslash or a control character, or when any component of the root directory
// or the lockfile is a symbolic link or not what it should be. The same
// "no symbolic link anywhere" rule as onboarding/lib/safe-path.mjs: deciding
// whether a link stays inside the checkout is a resolve-and-compare with cases;
// refusing links has none. Callers that run scanners treat any rejection as a
// failure of the dependency control, so a refused root fails closed.
import { execFile } from 'node:child_process';
import { lstat, readdir, realpath } from 'node:fs/promises';
import { isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

// In npm's order of precedence: a shrinkwrap wins over a package-lock.
export const NPM_LOCKFILES = ['npm-shrinkwrap.json', 'package-lock.json'];

const CONTROL = /[\u0000-\u001f\u007f]/;

// Why a repository path cannot be used lexically, or null when it can.
export function unsafePathReason(path) {
  if (typeof path !== 'string' || path === '') {
    return 'empty path';
  }
  if (CONTROL.test(path)) {
    return 'contains a control character';
  }
  if (path.includes('\\')) {
    return 'contains a backslash';
  }
  if (path.startsWith('/') || isAbsolute(path) || /^[a-zA-Z]:/.test(path)) {
    return 'is absolute';
  }
  const segments = path.split('/');
  if (segments.includes('..')) {
    return "contains a '..' segment";
  }
  if (segments.some((segment) => segment === '' || segment === '.')) {
    return "contains an empty or '.' segment";
  }
  return null;
}

const inNodeModules = (path) => path.split('/').includes('node_modules');

const byRoot = (a, b) => (a.root === b.root ? 0 : a.root === '.' ? -1 : b.root === '.' ? 1 : a.root < b.root ? -1 : 1);

// Pure: npm dependency roots from a list of repository-relative (posix) paths,
// all assumed tracked. Deterministic and duplicate-free whatever the input
// order or repetition.
//
//   roots     [{ root, lockfile }]   root '.' first, then by path
//   rejected  [{ path, reason }]     lockfile paths refused as unsafe
//   shadowed  [{ path, by }]         package-lock.json ignored by npm because
//                                    npm-shrinkwrap.json sits next to it
export function npmDependencyRoots(files) {
  const byDirectory = new Map();
  const rejected = new Map();
  for (const path of new Set(files)) {
    if (typeof path !== 'string') {
      continue;
    }
    const name = posix.basename(path);
    if (!NPM_LOCKFILES.includes(name) || inNodeModules(path)) {
      continue;
    }
    const reason = unsafePathReason(path);
    if (reason) {
      rejected.set(path, { path, reason: `${JSON.stringify(path)} ${reason}` });
      continue;
    }
    const root = posix.dirname(path);
    byDirectory.set(root, [...(byDirectory.get(root) ?? []), name]);
  }
  const roots = [];
  const shadowed = [];
  for (const [root, names] of byDirectory) {
    const lockName = NPM_LOCKFILES.find((candidate) => names.includes(candidate));
    const lockfile = root === '.' ? lockName : `${root}/${lockName}`;
    roots.push({ root, lockfile });
    for (const other of NPM_LOCKFILES.filter((candidate) => candidate !== lockName && names.includes(candidate))) {
      shadowed.push({ path: root === '.' ? other : `${root}/${other}`, by: lockfile });
    }
  }
  return {
    roots: roots.sort(byRoot),
    rejected: [...rejected.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
    shadowed: shadowed.sort((a, b) => (a.path < b.path ? -1 : 1))
  };
}

async function walk(root, dir = root, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === 'node_modules') {
      continue;
    }
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(root, full, out);
    } else if (entry.isFile() || entry.isSymbolicLink()) {
      // A symbolic link is listed (never followed) so that a linked lockfile is
      // REFUSED by the confinement check rather than silently not seen.
      out.push(relative(root, full).split(sep).join('/'));
    }
  }
  return out;
}

// Tracked files of the checkout at `repoDir`, repository-relative.
export async function listTrackedFiles(repoDir) {
  try {
    const { stdout } = await run('git', ['-C', repoDir, 'ls-files', '-z', '--cached'], { maxBuffer: 256 * 1024 * 1024 });
    return { files: [...new Set(stdout.split('\0').filter(Boolean))].sort(), source: 'git' };
  } catch {
    return { files: (await walk(resolve(repoDir))).sort(), source: 'filesystem' };
  }
}

// Filesystem confinement of one root: every component of the root directory
// must be a real directory and the lockfile a regular file — no symbolic link
// anywhere — and the root must resolve inside the checkout. Returns the reason
// it is refused, or null.
export async function rootConfinementProblem(repoDir, { root, lockfile }) {
  let base;
  try {
    base = await realpath(resolve(repoDir));
  } catch (error) {
    return `the checkout ${repoDir} could not be resolved: ${error.message}`;
  }
  const segments = root === '.' ? [] : root.split('/');
  let current = base;
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const shown = segments.slice(0, index + 1).join('/');
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      return `'${shown}' could not be checked: ${error.code ?? error.message}`;
    }
    if (info.isSymbolicLink()) {
      return `'${shown}' is a symbolic link; npm audit never runs through a symbolic link`;
    }
    if (!info.isDirectory()) {
      return `'${shown}' is not a directory`;
    }
  }
  let lockInfo;
  try {
    lockInfo = await lstat(join(base, ...lockfile.split('/')));
  } catch (error) {
    return `'${lockfile}' could not be checked: ${error.code ?? error.message}`;
  }
  if (lockInfo.isSymbolicLink()) {
    return `'${lockfile}' is a symbolic link; npm audit never reads a linked lockfile`;
  }
  if (!lockInfo.isFile()) {
    return `'${lockfile}' is not a regular file`;
  }
  try {
    const resolved = await realpath(current);
    const rel = relative(base, resolved);
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      return `'${root}' resolves outside the checkout`;
    }
  } catch (error) {
    return `'${root}' could not be resolved: ${error.message}`;
  }
  return null;
}

// Every npm dependency root of the checkout at `repoDir`, with each root proven
// confined. A root that fails confinement moves to `rejected`; nothing is
// dropped without a record.
export async function discoverNpmRoots(repoDir = '.') {
  const { files, source } = await listTrackedFiles(repoDir);
  const found = npmDependencyRoots(files);
  const roots = [];
  const rejected = [...found.rejected];
  for (const entry of found.roots) {
    const problem = await rootConfinementProblem(repoDir, entry);
    if (problem) {
      rejected.push({ path: entry.lockfile, reason: problem });
    } else {
      roots.push(entry);
    }
  }
  return { roots, rejected: rejected.sort((a, b) => (a.path < b.path ? -1 : 1)), shadowed: found.shadowed, source };
}

// The roots a scanner or the gate may rely on; throws when any root was refused,
// because a refused root is a dependency project nobody audited.
export async function requireNpmRoots(repoDir = '.') {
  const result = await discoverNpmRoots(repoDir);
  if (result.rejected.length > 0) {
    throw new Error(
      `npm dependency root(s) refused, so npm audit cannot cover them: ${result.rejected
        .map((entry) => `${entry.path} (${entry.reason})`)
        .join('; ')}`
    );
  }
  return result.roots;
}
