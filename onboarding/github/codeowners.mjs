// CODEOWNERS for `github plan --scope protection`: PURE.
//
// Two different facts, never merged:
//   - REMOTE (GitHub): which CODEOWNERS file GitHub uses on the default branch
//     (its lookup order: .github/, root, docs/), whether it is within GitHub's
//     size limit, and GitHub's own parse errors for it (unknown owners, bad
//     syntax). Required code-owner REVIEW is a separate remote fact, judged in
//     protection.mjs.
//   - HEURISTIC: whether that file's rules appear to cover the SSD control
//     paths, judged by ssd-onboard's conservative local matcher
//     (lib/analyze.mjs). It is "appears complete", never proof that GitHub
//     will request those owners.
// Coverage is judged on GITHUB'S copy of the file; a local copy that differs is
// a warning, because the local heuristic would otherwise describe a file
// GitHub does not use.
import { codeownersCovers, securityOwnedPaths } from '../lib/analyze.mjs';
import { gitBlobSha } from './discover.mjs';

const MAX_LISTED = 10;

// remote: discoverCodeowners() result.
// -> { state: complete | incomplete | unverified, path, reasons, warnings, uncovered, errors }
export function analyzeCodeowners({ config, facts, remote }) {
  const out = { state: 'unverified', path: null, reasons: [], warnings: [], uncovered: [], errors: [] };
  const branch = config.repository.defaultBranch;
  const local = facts?.codeowners ?? null;
  if (remote.state === 'unverified') {
    out.reasons.push(`the CODEOWNERS file GitHub uses could not be determined (${remote.reason})`);
    return out;
  }
  if (remote.state === 'absent') {
    out.state = 'incomplete';
    out.reasons.push(`no CODEOWNERS file on ${branch} in .github/, the root or docs/: GitHub has no code owners to require, so code-owner review protects nothing. ssd-onboard never invents owners — add one with real owners`);
    if (local) {
      out.warnings.push(`${local} exists locally but not on ${branch} on GitHub (not merged yet?)`);
    }
    return out;
  }
  const file = remote.file;
  out.path = file.path;
  if (local && local !== file.path) {
    out.warnings.push(`the local CODEOWNERS is ${local}, but GitHub uses ${file.path} on ${branch}`);
  } else if (local && typeof facts.codeownersText === 'string' && gitBlobSha(facts.codeownersText) !== file.sha) {
    out.warnings.push(`the local ${local} differs from GitHub's copy on ${branch}; coverage below is judged on GitHub's copy`);
  } else if (!local) {
    out.warnings.push(`GitHub uses ${file.path} on ${branch}, but this checkout has no CODEOWNERS`);
  }
  if (file.tooLarge) {
    out.state = 'incomplete';
    out.reasons.push(`${file.path} is ${file.size} bytes; GitHub does not load a CODEOWNERS file over 3 MB`);
    return out;
  }
  const problems = [];
  if (remote.errors.state !== 'present') {
    out.reasons.push(`GitHub's parse errors for ${file.path} could not be read (${remote.errors.reason})`);
  } else if (remote.errors.list.length > 0) {
    out.errors = remote.errors.list.slice(0, MAX_LISTED);
    problems.push(`GitHub reports ${remote.errors.list.length} error(s) in ${file.path} (owners it does not recognise, or invalid lines)`);
  }
  if (file.text === null) {
    out.reasons.push(`GitHub did not return the content of ${file.path}, so its coverage could not be checked`);
  } else {
    out.uncovered = securityOwnedPaths(config).filter((path) => !codeownersCovers(file.text, path));
    if (out.uncovered.length > 0) {
      problems.push(`${file.path} on ${branch} does not appear to cover: ${out.uncovered.join(' ')}`);
    }
  }
  if (problems.length > 0) {
    out.state = 'incomplete';
    out.reasons.push(...problems);
  } else if (out.reasons.length === 0) {
    out.state = 'complete';
    out.reasons.push(`${file.path} on ${branch}: GitHub reports no errors, and it appears to cover every SSD control path (local heuristic matcher over GitHub's copy)`);
  }
  return out;
}
