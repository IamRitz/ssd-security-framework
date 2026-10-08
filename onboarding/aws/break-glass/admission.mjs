// Which framework commits may be ADMITTED to an environment's allowed set
// (Phase 3D, docs/break-glass-repositories.md § The allowed-commit parameter).
//
// `aws plan --scope break-glass-governance` refuses, and its `aws verify`
// reports as FAIL, any listed commit that:
//   - is not a commit of the framework checkout the command runs from;
//   - has a .github/workflows/_break-glass-lambda.yml without the Phase 3D
//     binding (its FIRST step `id: bind-framework-commit`, every checkout at
//     `ref: ${{ steps.bind-framework-commit.outputs.sha }}`), or that still
//     checks out `inputs.toolkit_ref`. Admitting such a commit would let a
//     caller-chosen toolkit run under the admitted commit's identity;
//   - for PRODUCTION only: is not an ancestor of refs/remotes/origin/main (the
//     reviewed, merged history). Synthetic may admit an unmerged candidate,
//     explicitly, to test it live; it is never thereby production's.
//
// git is read through an injected interface (lib/framework.mjs frameworkGit, or a test
// fake): no network, nothing fetched. origin/main is whatever the checkout
// last fetched; the commit checked against is recorded.
import { frameworkGit } from '../../lib/framework.mjs';

// Nothing under onboarding/aws runs a process: the git reader lives with the
// framework binding (lib/framework.mjs), which already reads git.
export { frameworkGit };

export const BINDING_WORKFLOW = '.github/workflows/_break-glass-lambda.yml';
export const ORIGIN_MAIN = 'refs/remotes/origin/main';
const BIND_ID = 'bind-framework-commit';
const BOUND_REF = /^\s*ref:\s*\$\{\{\s*steps\.bind-framework-commit\.outputs\.sha\s*\}\}\s*$/;
const TOOLKIT_REF = /^\s*ref:\s*\$\{\{\s*inputs\.toolkit_ref\s*\}\}\s*$/;
const CHECKOUT = /^\s*(?:-\s+)?uses:\s*actions\/checkout@/;
const STEP_START = /^(\s*)-\s+\S/;

// The workflow text at one commit -> problems[] (empty: it binds itself).
// Deliberately structural and strict: the binding step must be the job's
// FIRST step, no checkout may come before it, every checkout must use the
// bound commit, and nothing may check out inputs.toolkit_ref.
export function bindingProblems(text) {
  if (typeof text !== 'string') return [`${BINDING_WORKFLOW} does not exist at this commit`];
  const lines = text.split('\n');
  const problems = [];
  const bindLines = lines.flatMap((line, i) => (new RegExp(`^\\s*id:\\s*${BIND_ID}\\s*$`).test(line) ? [i] : []));
  if (bindLines.length !== 1) {
    problems.push(`${BINDING_WORKFLOW} has ${bindLines.length === 0 ? 'no' : 'more than one'} step with id ${BIND_ID}`);
  }
  const checkouts = lines.flatMap((line, i) => (CHECKOUT.test(line) ? [i] : []));
  if (checkouts.length === 0) problems.push(`${BINDING_WORKFLOW} has no actions/checkout step`);
  if (lines.some((line) => TOOLKIT_REF.test(line))) problems.push(`${BINDING_WORKFLOW} still checks out inputs.toolkit_ref`);
  const stepEnd = (from) => {
    const indent = STEP_START.exec(lines[from])?.[1] ?? /^(\s*)/.exec(lines[from])[1];
    for (let i = from + 1; i < lines.length; i += 1) {
      const m = STEP_START.exec(lines[i]);
      if ((m && m[1].length <= indent.length) || (lines[i].trim() !== '' && /^(\s*)/.exec(lines[i])[1].length < indent.length)) return i;
    }
    return lines.length;
  };
  // The start line of the step containing line i.
  const stepStartOf = (i) => {
    for (let j = i; j >= 0; j -= 1) if (STEP_START.test(lines[j])) return j;
    return -1;
  };
  for (const at of checkouts) {
    const start = STEP_START.test(lines[at]) ? at : stepStartOf(at);
    const body = lines.slice(start, stepEnd(start));
    if (!body.some((line) => BOUND_REF.test(line))) problems.push(`${BINDING_WORKFLOW} line ${at + 1}: a checkout that is not at steps.${BIND_ID}.outputs.sha`);
  }
  if (bindLines.length === 1) {
    const bindStep = stepStartOf(bindLines[0]);
    if (checkouts.some((at) => at < bindLines[0])) problems.push(`${BINDING_WORKFLOW}: a checkout runs before the ${BIND_ID} step`);
    // The job's first step: the nearest preceding `steps:` must have no other
    // step between it and the binding step.
    let stepsLine = -1;
    for (let j = bindStep; j >= 0; j -= 1) {
      if (/^\s*steps:\s*$/.test(lines[j])) {
        stepsLine = j;
        break;
      }
    }
    const between = stepsLine === -1 ? [] : lines.slice(stepsLine + 1, bindStep).filter((line) => STEP_START.test(line));
    if (stepsLine === -1 || between.length > 0) problems.push(`${BINDING_WORKFLOW}: the ${BIND_ID} step is not the job's first step`);
  }
  return problems;
}

// -> { findings: [{ severity, kind, message }], observed: [], originMain: sha | null }
//   environment  production | synthetic      shas  the commits to admit
//   git          frameworkGit() or a fake    severity  of a refusal (FAIL)
export async function admissionFindings({ environment, shas, git }) {
  const findings = [];
  const observed = [];
  const fail = (kind, message) => findings.push({ severity: 'FAIL', kind, message });
  const unverified = (kind, message) => findings.push({ severity: 'NOT VERIFIED', kind, message });
  let originMain = null;
  if (environment === 'production' && shas.length > 0) {
    originMain = await git.resolve(ORIGIN_MAIN);
    if (!originMain) {
      // Without the reviewed history nothing can be shown merged: refuse.
      fail('origin-main-unknown', `${ORIGIN_MAIN} cannot be resolved in the framework checkout (fetch it): no production commit can be shown to be merged`);
    } else {
      observed.push(`${ORIGIN_MAIN} = ${originMain}`);
    }
  }
  for (const sha of shas) {
    const isCommit = await git.isCommit(sha);
    if (isCommit === null) {
      unverified('git-unavailable', `${sha}: git could not answer whether it is a commit`);
      continue;
    }
    if (!isCommit) {
      fail('commit-missing', `${sha} is not a commit of the framework checkout (fetch it, or remove it from the policy)`);
      continue;
    }
    const problems = bindingProblems(await git.show(sha, BINDING_WORKFLOW));
    for (const p of problems) fail('binding-missing', `${sha}: ${p}`);
    if (environment === 'production' && originMain) {
      const ancestor = await git.isAncestor(sha, ORIGIN_MAIN);
      if (ancestor === null) unverified('git-unavailable', `${sha}: git could not answer whether it is merged to ${ORIGIN_MAIN}`);
      else if (!ancestor) fail('not-merged', `${sha} is not an ancestor of ${ORIGIN_MAIN} (${originMain}): production admits only reviewed, merged commits`);
    }
    if (!findings.some((f) => f.message.startsWith(sha))) observed.push(`${sha}: admitted`);
  }
  return { findings, observed, originMain };
}
