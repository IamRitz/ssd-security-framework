// Filesystem confinement for every write ssd-onboard makes inside a consumer
// repository.
//
// THREAT
// ------
// The consumer checkout is untrusted input. `ssd-onboard` writes to paths built
// from the repository root plus a relative path (some of which — the baseline
// path — come from .ssd/onboarding.yml). A lexically-safe relative path is NOT
// enough: if the checkout contains
//
//     security -> /tmp/escape          (a symlinked directory component)
//
// then `writeFile(join(root, 'security/baseline/semgrep-baseline.json'))` lands
// in /tmp/escape even though the path holds no '..', `path.resolve()` keeps it
// under root lexically, and nothing about the string looks wrong. The same
// applies to removal: `rm(join(root, stale))` through a symlinked ancestor
// deletes somebody else's file.
//
// This module is the one reviewed implementation of real (filesystem, not
// lexical) confinement. Every consumer-repository write and remove goes through
// it. It does NOT apply to temp workspaces under os.tmpdir(), which the CLI
// creates itself with mkdtemp and owns entirely.
//
// SYMLINK POLICY: no symbolic link anywhere
// -----------------------------------------
// A path component that is a symbolic link is refused, whether it points inside
// the repository or outside it, and whether it is an ancestor or the final
// target. Deciding "this link stays inside the root" is a resolve-and-compare
// that has to be re-argued for every link, every nesting depth and every race;
// "no links at all" is one rule with no cases. ssd-onboard writes generated
// workflows, scanner configs, .ssd/onboarding.yml and the baseline — none of
// which has any reason to be a symbolic link — so nothing legitimate is lost.
// The check still resolves each existing ancestor and compares it against the
// canonical root, so a refusal does not depend on the symlink rule alone.
//
// TOCTOU
// ------
// The component walk is check-then-use: an attacker who can modify the checkout
// CONCURRENTLY with `ssd-onboard` can replace a directory with a symbolic link
// between the lstat and the write. Node exposes no openat2/RESOLVE_BENEATH, and
// this framework adds no native dependencies, so that residual race is not
// closed here. Two things narrow it:
//
//   * the final component is opened with O_NOFOLLOW (and, for a fresh write,
//     O_EXCL where the caller asked for it), so a swap of the LEAF to a symbolic
//     link is refused by the kernel at the moment of the write, not by an
//     earlier check;
//   * the walk runs immediately before the operation, and each operation
//     re-walks, so no decision is cached across calls.
//
// The threat this module DOES close is the realistic one: an untrusted
// repository whose contents are already on disk when ssd-onboard runs. It does
// not claim to be a sandbox against a local attacker racing the process; an
// attacker with concurrent write access to the checkout the tool was pointed at
// is outside the model.
import { constants as FS } from 'node:fs';
import { lstat, mkdir, open, realpath, rm } from 'node:fs/promises';
import { isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';

export class PathConfinementError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PathConfinementError';
    this.code = 'ERR_PATH_NOT_CONFINED';
  }
}

const refuse = (relativePath, reason) => {
  throw new PathConfinementError(`refusing '${relativePath}': ${reason}`);
};

// The repository-relative path as a list of components, or a refusal.
// Rejects absolute paths, drive-letter/UNC-looking paths, '..' in any position,
// and the empty path. '.' segments are dropped by normalize().
function components(relativePath) {
  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    refuse(String(relativePath), 'a repository-relative path is required');
  }
  if (isAbsolute(relativePath) || /^[a-zA-Z]:/.test(relativePath) || relativePath.startsWith('\\')) {
    refuse(relativePath, 'an absolute path is not a repository-relative path');
  }
  const parts = normalize(relativePath).split(/[\\/]+/).filter((part) => part !== '' && part !== '.');
  if (parts.length === 0) {
    refuse(relativePath, 'a repository-relative path is required');
  }
  if (parts.includes('..')) {
    refuse(relativePath, 'the path escapes the repository root');
  }
  return parts;
}

// True when `child` is `root` itself or lies beneath it, compared on already
// canonical (realpath'd) absolute paths.
//
// Only an ACTUAL parent traversal disqualifies a child. A leading '..' in the
// relative path is not enough: `relative(root, root + '/..cache')` is
// '..cache', a perfectly ordinary name for a directory inside the repository.
// The traversal cases are exactly '..' itself and anything under `..<sep>`.
function within(root, child) {
  if (child === root) {
    return true;
  }
  const rel = relative(root, child);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

async function canonicalRoot(root, relativePath) {
  try {
    return await realpath(resolve(root));
  } catch (error) {
    // Fail closed: if the root cannot be canonicalized there is nothing to
    // confine writes to.
    refuse(relativePath, `the repository root ${root} could not be resolved: ${error.message}`);
  }
}

/**
 * Resolves `relativePath` inside `root` and proves it is really confined there.
 *
 * The algorithm:
 *   1. reject absolute paths and any '..' component (lexical screen);
 *   2. canonicalize `root` with realpath — every later comparison is against
 *      that canonical root, so a symlinked root directory is handled once;
 *   3. walk the components from the canonical root downwards, lstat-ing each
 *      one in turn:
 *        - ENOENT: this component and everything below it is missing. Nothing
 *          further can be traversed, so the walk stops; the caller may create
 *          the missing components (safeMkdir / safeWriteFile create parents),
 *          and each creation is an ordinary mkdir under a directory already
 *          proven to be inside the root.
 *        - a symbolic link: refused (see the policy above), leaf included.
 *        - any other lstat error: refused. Fail closed on uncertainty.
 *        - an existing non-final component that is not a directory: refused,
 *          rather than letting the write fail with ENOTDIR halfway through.
 *   4. realpath the deepest EXISTING ancestor and require it to be within the
 *      canonical root. With no symbolic links in the walk this is implied, but
 *      it is checked anyway so confinement never rests on the symlink rule
 *      alone (e.g. a bind mount, or a component that changed under us).
 *
 * `relativePath` may name something that does not exist — that is the normal
 * case for a file about to be created — and a missing LEAF is never an error
 * here. Callers that require the leaf to exist (safeRemove without `force`)
 * find out from the operation itself.
 *
 * Returns the absolute path to operate on, under the canonical root.
 */
export async function assertSafeRepoPath(root, relativePath) {
  const parts = components(relativePath);
  const base = await canonicalRoot(root, relativePath);
  let current = base;
  let deepestExisting = base;
  for (const [index, part] of parts.entries()) {
    current = join(current, part);
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      if (error.code === 'ENOENT') {
        break; // missing from here down; nothing left to traverse
      }
      refuse(relativePath, `'${parts.slice(0, index + 1).join('/')}' could not be checked: ${error.message}`);
    }
    if (info.isSymbolicLink()) {
      refuse(
        relativePath,
        `'${parts.slice(0, index + 1).join('/')}' is a symbolic link; ssd-onboard does not write through symbolic links`
      );
    }
    if (index < parts.length - 1 && !info.isDirectory()) {
      refuse(relativePath, `'${parts.slice(0, index + 1).join('/')}' is not a directory`);
    }
    deepestExisting = current;
  }
  let resolved;
  try {
    resolved = await realpath(deepestExisting);
  } catch (error) {
    refuse(relativePath, `'${relative(base, deepestExisting) || '.'}' could not be resolved: ${error.message}`);
  }
  if (!within(base, resolved)) {
    refuse(relativePath, `'${relative(base, deepestExisting) || '.'}' resolves outside the repository root`);
  }
  return join(base, ...parts);
}

// mkdir -p for the confined path itself. Each component is created under a
// directory already proven to be inside the root; a component that turns out to
// exist as a symbolic link is caught by the walk in assertSafeRepoPath.
export async function safeMkdir(root, relativePath) {
  const target = await assertSafeRepoPath(root, relativePath);
  await mkdir(target, { recursive: true });
  return target;
}

// The parent directory of a confined path, created if missing. Returns the
// confined absolute target.
async function confinedTarget(root, relativePath, { createParents = true } = {}) {
  const target = await assertSafeRepoPath(root, relativePath);
  if (createParents) {
    const parts = components(relativePath);
    if (parts.length > 1) {
      await safeMkdir(root, parts.slice(0, -1).join('/'));
      // Creating the parents may have raced; re-prove the whole path.
      return assertSafeRepoPath(root, relativePath);
    }
  }
  return target;
}

/**
 * Writes `data` to `root`/`relativePath`, confined.
 *
 * `flag` mirrors fs.writeFile: 'w' (default) truncates or creates, 'wx' refuses
 * an existing file. Either way the file is opened with O_NOFOLLOW, so the write
 * fails rather than following a symbolic link that appeared at the leaf after
 * the walk. `mode` is passed through to open().
 */
export async function safeWriteFile(root, relativePath, data, { flag = 'w', mode = 0o666, createParents = true } = {}) {
  if (flag !== 'w' && flag !== 'wx') {
    throw new TypeError(`safeWriteFile: unsupported flag '${flag}'`);
  }
  const target = await confinedTarget(root, relativePath, { createParents });
  const flags = FS.O_WRONLY | FS.O_CREAT | FS.O_NOFOLLOW | (flag === 'wx' ? FS.O_EXCL : FS.O_TRUNC);
  let handle;
  try {
    handle = await open(target, flags, mode);
  } catch (error) {
    if (error.code === 'ELOOP') {
      refuse(relativePath, `'${relativePath}' is a symbolic link; ssd-onboard does not write through symbolic links`);
    }
    throw error;
  }
  try {
    await handle.writeFile(data);
  } finally {
    await handle.close();
  }
  return target;
}

/**
 * Removes `root`/`relativePath`, confined.
 *
 * Removal is guarded exactly like a write: an ancestor that is a symbolic link,
 * or a leaf that is one, is refused before anything is unlinked — so a stale
 * generated file "at" a symlinked path is never used to delete the link's
 * target, and the link itself is not quietly removed either.
 */
export async function safeRemove(root, relativePath, { recursive = false, force = false } = {}) {
  const target = await assertSafeRepoPath(root, relativePath);
  await rm(target, { recursive, force });
  return target;
}
