// Repository inspection: READ-ONLY facts about the consumer checkout.
//
// Uses the filesystem and `git` (read-only subcommands only). It never calls the
// AWS CLI, never calls `gh`, and writes nothing.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, posix, relative, sep } from 'node:path';
import { promisify } from 'node:util';

import { classifyManifests, suggestIgnores, suggestRulesets } from './coverage.mjs';
import { readMarker } from './files.mjs';

const run = promisify(execFile);

async function git(root, args) {
  try {
    const { stdout } = await run('git', ['-C', root, ...args], { maxBuffer: 64 * 1024 * 1024 });
    return stdout;
  } catch {
    return null;
  }
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
    } else if (entry.isFile()) {
      out.push(relative(root, full).split(sep).join('/'));
    }
  }
  return out;
}

// Tracked files plus untracked-but-not-ignored ones: what a commit of this
// working tree would contain. Falls back to a filesystem walk outside git.
export async function listRepositoryFiles(root) {
  const output = await git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  if (output !== null) {
    const files = [...new Set(output.split('\0').filter(Boolean))];
    const present = [];
    for (const file of files) {
      try {
        if ((await stat(join(root, file))).isFile()) {
          present.push(file);
        }
      } catch {
        // deleted in the working tree
      }
    }
    return { files: present.sort(), source: 'git' };
  }
  return { files: (await walk(root)).sort(), source: 'filesystem (not a git repository; .git and node_modules skipped)' };
}

export function parseGithubSlug(url) {
  const match = /github\.com[:/]+([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(url?.trim() ?? '');
  return match ? `${match[1]}/${match[2]}` : null;
}

export async function gitFacts(root) {
  const remote = await git(root, ['remote', 'get-url', 'origin']);
  const originHead = await git(root, ['symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD']);
  const current = await git(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
  return {
    isGit: (await git(root, ['rev-parse', '--is-inside-work-tree']))?.trim() === 'true',
    slug: parseGithubSlug(remote),
    defaultBranch: originHead?.trim().replace(/^origin\//, '') || null,
    currentBranch: current?.trim() || null
  };
}

async function readTextOrNull(path) {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

// What `baseline accept` binds a candidate to: the exact checkout it is run in.
export async function consumerGitState(root) {
  const head = (await git(root, ['rev-parse', '--verify', '--quiet', 'HEAD']))?.trim() ?? null;
  const status = await git(root, ['status', '--porcelain', '--untracked-files=no']);
  let semgrepignoreSha256 = null;
  try {
    semgrepignoreSha256 = createHash('sha256').update(await readFile(join(root, '.semgrepignore'))).digest('hex');
  } catch {
    // absent
  }
  return {
    head,
    clean: status !== null && status.trim() === '',
    slug: parseGithubSlug(await git(root, ['remote', 'get-url', 'origin'])),
    semgrepignoreSha256
  };
}

export async function inspectRepository(root) {
  const { files, source } = await listRepositoryFiles(root);
  // Only the manifests the classifier parses are read.
  const texts = new Map();
  for (const file of files) {
    const name = posix.basename(file);
    if (['package.json', 'package-lock.json', 'pyproject.toml'].includes(name) && !/(^|\/)node_modules\//.test(file)) {
      texts.set(file, await readTextOrNull(join(root, file)));
    }
  }
  const { manifests, vendored } = classifyManifests(files, (file) => texts.get(file) ?? null);

  const workflowFiles = files.filter((file) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(file));
  const workflows = [];
  for (const file of workflowFiles) {
    const text = await readTextOrNull(join(root, file));
    workflows.push({ path: file, marker: readMarker(text ?? '') });
  }

  const dockerfiles = files.filter((file) => /(^|\/)(?:Dockerfile|Containerfile)(?:\.[^/]+)?$|\.dockerfile$/i.test(file));
  const codeowners = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'].find((path) => files.includes(path)) ?? null;

  return {
    root,
    fileSource: source,
    files,
    git: await gitFacts(root),
    manifests,
    vendoredNodeModules: vendored,
    rulesetSuggestion: suggestRulesets(files),
    ignoreSuggestions: suggestIgnores(files),
    dockerfiles,
    workflows,
    codeowners,
    codeownersText: codeowners ? await readTextOrNull(join(root, codeowners)) : null,
    semgrepignore: await readTextOrNull(join(root, '.semgrepignore')),
    readText: (path) => readTextOrNull(join(root, path)),
    exists: async (path) => {
      try {
        await stat(join(root, path));
        return true;
      } catch {
        return false;
      }
    }
  };
}
