// Ecosystem detection for the dependency-scanning stage.
//
// The security framework must work for any onboarded repo, not just Node ones.
// This inspects a checkout and reports which dependency ecosystems are present,
// so the pipeline can run the right language-native scanner (npm audit for npm,
// pip-audit for Python) and the gate can require the matching report. Both can
// be true (a monorepo); neither is a clean skip, not a failure. OSV-Scanner runs
// regardless and is the cross-ecosystem backstop.
import { access, appendFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// A manifest OR a lockfile is enough to call an ecosystem present — a repo may be
// checked out before a lockfile is generated, and the gate/scanner should still
// engage rather than silently skip.
const NPM_MARKERS = ['package-lock.json', 'package.json'];
// requirements.txt / Pipfile.lock are direct pip-audit/OSV inputs; poetry.lock
// and pyproject.toml mark a Python project even when no requirements.txt exists
// (OSV-Scanner parses poetry.lock/Pipfile.lock natively).
const PYTHON_MARKERS = ['requirements.txt', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml'];

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function firstPresent(dir, markers) {
  for (const marker of markers) {
    if (await exists(join(dir, marker))) {
      return marker;
    }
  }
  return null;
}

// Returns { npm, python, npmMarker, pythonMarker, requirementsTxt } for `dir`.
// requirementsTxt is the pip-audit `-r` target when a requirements.txt is present
// (its safe, resolution-free input); Python projects without one rely on OSV.
export async function detectEcosystems(dir = '.') {
  const root = resolve(dir);
  const npmMarker = await firstPresent(root, NPM_MARKERS);
  const pythonMarker = await firstPresent(root, PYTHON_MARKERS);
  // Audit targets: the specific files each language-native scanner consumes.
  // npm audit --package-lock-only needs package-lock.json; pip-audit -r needs a
  // requirements.txt. These, not the broad ecosystem flags, decide whether a
  // report is required — a poetry-only repo is `python: true` but has no
  // requirements.txt, so pip-audit does not run and OSV-Scanner covers it.
  const hasPackageLock = await exists(join(root, 'package-lock.json'));
  const hasRequirements = await exists(join(root, 'requirements.txt'));
  return {
    npm: npmMarker !== null,
    python: pythonMarker !== null,
    npmMarker,
    pythonMarker,
    packageLock: hasPackageLock,
    requirementsTxt: hasRequirements ? 'requirements.txt' : null
  };
}

function parseArguments(argv) {
  const options = { dir: '.', githubOutput: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--dir') {
      options.dir = argv[index + 1];
      index += 1;
    } else if (argument === '--github-output') {
      options.githubOutput = true;
    } else {
      throw new Error(`unknown argument ${argument}`);
    }
  }
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const result = await detectEcosystems(options.dir);

  const npmNote = result.npm ? `npm (found ${result.npmMarker})` : 'npm: none';
  const pythonNote = result.python ? `python (found ${result.pythonMarker})` : 'python: none';
  console.log(`Ecosystem detection in ${resolve(options.dir)}: ${npmNote}; ${pythonNote}`);
  if (!result.npm && !result.python) {
    console.log('No npm or Python dependency manifests found; language-native audits will be skipped (OSV-Scanner still runs).');
  }

  if (options.githubOutput && process.env.GITHUB_OUTPUT) {
    await appendFile(
      process.env.GITHUB_OUTPUT,
      `npm=${result.npm}\npython=${result.python}\n` +
        `package_lock=${result.packageLock}\nrequirements_txt=${result.requirementsTxt ?? ''}\n`
    );
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
