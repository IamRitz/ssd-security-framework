// Binding the generator to the framework revision it generates for.
//
// ssd-onboard's templates are code at some framework commit X; the workflows it
// writes call the framework at `framework.ref` Y. If X != Y, the output assumes
// X's reusable-workflow contracts while running against Y's. So generation is
// allowed only when:
//
//   - this CLI runs from a git checkout of the framework (the commit is knowable),
//   - that checkout is CLEAN (its templates really are commit X, not X plus edits),
//   - its origin is framework.repository, and
//   - framework.ref (an exact 40-character SHA — enforced by the schema) == X.
//
// The reusable-workflow contracts are then read from the immutable git object
// `X:.github/workflows/<file>` — never from `main`, `v1`, another moving ref,
// or a working tree that differs from X.
import { execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { parseGithubSlug } from './inspect.mjs';

const run = promisify(execFile);
export const FRAMEWORK_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

async function git(root, args) {
  try {
    return (await run('git', ['-C', root, ...args], { maxBuffer: 16 * 1024 * 1024 })).stdout;
  } catch {
    return null;
  }
}

// { root, sha, clean, dirtyPaths, slug, readWorkflow(file) } or null when this
// CLI is not running from a git checkout of the framework.
export async function detectFramework(root = FRAMEWORK_ROOT) {
  const head = (await git(root, ['rev-parse', '--verify', '--quiet', 'HEAD']))?.trim();
  if (!head || !/^[0-9a-f]{40}$/.test(head)) {
    return null;
  }
  const status = (await git(root, ['status', '--porcelain', '--untracked-files=all'])) ?? '';
  const dirtyPaths = status.split('\n').filter(Boolean).map((line) => line.slice(3));
  const origin = (await git(root, ['remote', 'get-url', 'origin']))?.trim() ?? null;
  return {
    root,
    sha: head,
    clean: dirtyPaths.length === 0,
    dirtyPaths,
    slug: parseGithubSlug(origin),
    readWorkflow: async (file) => {
      if (!/^[A-Za-z0-9._-]+\.ya?ml$/.test(file)) {
        return null;
      }
      return git(root, ['show', `${head}:.github/workflows/${file}`]);
    }
  };
}

// Blocking problems with the generator/ref binding. Empty means bound.
export function frameworkProblems(framework, config) {
  if (!framework) {
    return [
      'cannot determine the framework commit this ssd-onboard runs from. Run it from a git checkout of the framework at the exact framework.ref (docs/onboarding-cli.md § Obtaining ssd-onboard)'
    ];
  }
  const problems = [];
  if (!framework.clean) {
    const shown = framework.dirtyPaths.slice(0, 5).join(', ');
    problems.push(
      `the ssd-onboard checkout at ${framework.sha} has uncommitted changes (${shown}${framework.dirtyPaths.length > 5 ? ', …' : ''}); its templates are not the commit it claims to be. Use a clean checkout`
    );
  }
  if (framework.slug && config.framework.repository && framework.slug.toLowerCase() !== config.framework.repository.toLowerCase()) {
    problems.push(`this ssd-onboard checkout's origin is ${framework.slug}, but framework.repository is ${config.framework.repository}`);
  }
  if (config.framework.ref && config.framework.ref !== framework.sha) {
    problems.push(
      `framework.ref ${config.framework.ref} is not the commit this ssd-onboard runs from (${framework.sha}). The generated workflows would call one revision with templates written for another. Check out the framework at framework.ref (git checkout --detach ${config.framework.ref}) and run ssd-onboard from there, or change framework.ref deliberately`
    );
  }
  return problems;
}

// Phase 3D admission (onboarding/aws/break-glass/admission.mjs): local git
// questions about OTHER commits of the framework checkout. Read-only, no
// network, nothing fetched.
const COMMIT = /^[0-9a-f]{40}$/;
// git over the framework checkout at `root`. Every method answers from local
// objects only and never throws: an unanswerable question is null.
export function frameworkGit(root) {
  const git = async (args) => {
    try {
      return { ok: true, stdout: (await run('git', ['-C', root, ...args], { maxBuffer: 4 * 1024 * 1024 })).stdout };
    } catch (error) {
      return { ok: false, code: typeof error?.code === 'number' ? error.code : null };
    }
  };
  return {
    // -> true | false | null (git could not answer)
    async isCommit(sha) {
      const r = await git(['cat-file', '-t', sha]);
      if (r.ok) return r.stdout.trim() === 'commit';
      return r.code === 128 ? false : null;
    },
    // -> 40-hex | null
    async resolve(ref) {
      const r = await git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
      const sha = r.ok ? r.stdout.trim() : '';
      return COMMIT.test(sha) ? sha : null;
    },
    // -> true | false | null. merge-base --is-ancestor exits 0 (yes) or 1 (no).
    async isAncestor(sha, ref) {
      const r = await git(['merge-base', '--is-ancestor', sha, ref]);
      if (r.ok) return true;
      return r.code === 1 ? false : null;
    },
    // -> file text at that commit | null
    async show(sha, path) {
      const r = await git(['show', `${sha}:${path}`]);
      return r.ok ? r.stdout : null;
    }
  };
}
