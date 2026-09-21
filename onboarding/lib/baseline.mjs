// The Semgrep baseline lifecycle. Accepting a baseline is a SECURITY DECISION —
// it permanently accepts every finding in it — so nothing here happens
// implicitly:
//
//   prepare  finds / downloads a CANDIDATE from a verified full-scan bootstrap
//            run into .ssd/candidates/. Never writes the baseline path.
//   accept   an explicit command that re-validates the candidate, shows every
//            finding, requires the finding count to be confirmed, and refuses
//            to overwrite an existing baseline.
//   promote  log-only -> enforce, only with a valid accepted baseline.
//
// Only Semgrep findings can ever be baselined: the framework's baseline format
// has no place for secret, dependency or image findings.
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { PROVENANCE_KIND, PROVENANCE_SCHEMA_VERSION, provenanceDigest } from '../../security/scripts/baseline-provenance.mjs';
import { semgrepScopeDigest } from './coverage.mjs';

export const CANDIDATE_DIR = '.ssd/candidates';
export const CANDIDATE_FILE = `${CANDIDATE_DIR}/semgrep-baseline.candidate.json`;
export const CANDIDATE_PROVENANCE = `${CANDIDATE_DIR}/semgrep-baseline.candidate.provenance.json`;
// The only run that may supply a baseline: a FULL-TREE workflow_dispatch scan of
// the configured default branch. pull_request and push scans are diff-aware;
// other branches are unsupported in this version rather than bypassable.
const ONBOARDING_EVENT = 'workflow_dispatch';

async function readJsonFile(path) {
  try {
    return { exists: true, value: JSON.parse(await readFile(path, 'utf8')) };
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { exists: false, value: null };
    }
    return { exists: true, value: null, error: error.message };
  }
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

const sameSet = (a, b) => a.length === b.length && [...a].sort().every((value, index) => value === [...b].sort()[index]);

// Validates a baseline document (committed or candidate) against the gate's own
// expectations (security-gate.mjs evaluateSemgrep) plus the config's rulesets.
// `requireProvenance`: a CANDIDATE must record the rulesets and scanner that
// produced it. An already-committed baseline may predate those fields; the gate
// accepts it, so it is reported rather than rejected (see rolloutState).
export function validateBaselineDocument(doc, { rulesets, requireProvenance = true } = {}) {
  const errors = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return ['is not a JSON object'];
  }
  if (doc.schemaVersion !== 1) {
    errors.push(`schemaVersion is ${JSON.stringify(doc.schemaVersion)}, expected 1`);
  }
  if (!Array.isArray(doc.findings)) {
    errors.push('has no findings array');
  } else {
    const seen = new Set();
    doc.findings.forEach((finding, index) => {
      if (!/^[0-9a-f]{64}$/.test(finding?.fingerprint ?? '')) {
        errors.push(`findings[${index}] has no sha256 fingerprint`);
      } else if (seen.has(finding.fingerprint)) {
        errors.push(`findings[${index}] duplicates fingerprint ${finding.fingerprint.slice(0, 12)}…`);
      } else {
        seen.add(finding.fingerprint);
      }
      if (typeof finding?.checkId !== 'string' || typeof finding?.path !== 'string') {
        errors.push(`findings[${index}] is missing checkId or path`);
      }
      const extra = Object.keys(finding ?? {}).filter((key) => !['fingerprint', 'checkId', 'path'].includes(key));
      if (extra.length > 0) {
        errors.push(`findings[${index}] carries unexpected fields (${extra.join(', ')}); a Semgrep baseline records fingerprints only`);
      }
    });
  }
  if (!Array.isArray(doc.rulesets) || doc.rulesets.length === 0) {
    if (requireProvenance) {
      errors.push('does not record the rulesets that produced it');
    }
  } else if (rulesets && !sameSet(doc.rulesets, rulesets)) {
    errors.push(
      `was generated with rulesets [${doc.rulesets.join(', ')}] but semgrep.rulesets is [${rulesets.join(', ')}]; ` +
        'a baseline that never saw the configured rules cannot accept their findings'
    );
  }
  if (requireProvenance && (typeof doc.generatedBy !== 'string' || !/^semgrep /.test(doc.generatedBy))) {
    errors.push('does not say it was generated from a Semgrep report (generatedBy)');
  }
  return errors;
}

export function scopeDigestFor(config, semgrepignoreText) {
  return semgrepScopeDigest({
    rulesets: config.semgrep.rulesets,
    roots: config.semgrep.roots,
    ignorePatterns: config.semgrep.ignore.managed
      ? config.semgrep.ignore.patterns
      : semgrepignoreText === null
        ? null
        : semgrepignoreText.split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'))
  });
}

// Derives the rollout state from config + files. Never stored twice.
export async function rolloutState(root, config) {
  const baselinePath = join(root, config.semgrep.baseline.path);
  const baseline = await readJsonFile(baselinePath);
  const candidate = await readJsonFile(join(root, CANDIDATE_FILE));
  const baselineErrors = baseline.exists
    ? baseline.value
      ? validateBaselineDocument(baseline.value, { rulesets: config.semgrep.rulesets, requireProvenance: false })
      : [`is not valid JSON (${baseline.error})`]
    : [];
  const warnings = [];
  if (baseline.value && !Array.isArray(baseline.value.rulesets)) {
    warnings.push(
      `${config.semgrep.baseline.path} does not record the rulesets it was generated with, so ssd-onboard cannot confirm it saw semgrep.rulesets`
    );
  }
  const { gateMode } = config.rollout;
  const { state } = config.semgrep.baseline;
  const problems = [];
  let name;
  if (state === 'absent') {
    if (baseline.exists) {
      name = 'inconsistent';
      problems.push(
        `${config.semgrep.baseline.path} exists but semgrep.baseline.state is 'absent'. If it is this repository's reviewed baseline, set state: accepted; if not, remove it in a reviewed pull request`
      );
    } else {
      name = candidate.exists ? 'candidate-downloaded' : 'onboarding';
    }
  } else if (!baseline.exists) {
    name = 'inconsistent';
    problems.push(
      `semgrep.baseline.state is 'accepted' but ${config.semgrep.baseline.path} does not exist. A missing baseline is a fail-closed BLOCK on every run; restore it from history — do not re-bootstrap`
    );
  } else if (baselineErrors.length > 0) {
    name = 'inconsistent';
    problems.push(...baselineErrors.map((error) => `${config.semgrep.baseline.path} ${error}`));
  } else {
    name = gateMode === 'enforce' ? 'enforcing' : 'baseline-accepted';
  }
  if (gateMode === 'enforce' && state !== 'accepted') {
    name = 'inconsistent';
  }
  return {
    name,
    problems,
    warnings,
    baseline: { path: config.semgrep.baseline.path, exists: baseline.exists, findings: baseline.value?.findings?.length ?? null },
    candidate: { exists: candidate.exists, findings: candidate.value?.findings?.length ?? null }
  };
}

export const NEXT_STEP = {
  onboarding: 'dispatch the bootstrap run, then `ssd-onboard baseline prepare --run <run-id>`',
  'candidate-downloaded': 'review .ssd/candidates/semgrep-baseline.candidate.json, then `ssd-onboard baseline accept`',
  'baseline-accepted': 'watch a few PRs in log-only, then `ssd-onboard promote --enforce`',
  enforcing: 'steady state — keep `ssd-onboard render --check` green',
  inconsistent: 'fix the problems above; nothing is generated from an inconsistent state'
};

// --- prepare ----------------------------------------------------------------------

export function dispatchInstructions(config) {
  const file = config.workflows.security.split('/').pop();
  return [
    'The bootstrap run must be a FULL scan, so it is started by workflow_dispatch (a pull_request',
    'scan is diff-aware and would omit the existing backlog). Dispatch it on the default branch:',
    '',
    `  gh workflow run ${file} --repo ${config.repository.slug} --ref ${config.repository.defaultBranch} -f bootstrap_baseline=true`,
    '',
    'or use "Run workflow" in the Actions tab with the bootstrap_baseline box ticked. When it finishes:',
    '',
    `  ssd-onboard baseline prepare --run <run-id>`,
    '',
    'ssd-onboard does not dispatch the run itself: this phase makes no GitHub mutations.',
    '',
    'To accept the candidate later, check out EXACTLY the commit that run scanned, with no',
    'local changes: acceptance is refused if HEAD, the Semgrep configuration, .semgrepignore,',
    'the repository or the framework ref differ from the scan.'
  ];
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const sorted = (list) => [...list].sort();
const sameList = (a, b) => JSON.stringify(sorted(a ?? [])) === JSON.stringify(sorted(b ?? []));

// The candidate and its provenance are internally consistent: the digest
// covers the record, and the record covers the candidate's exact bytes.
export function provenanceIntegrityProblems(provenance, candidateText) {
  const problems = [];
  if (!provenance || typeof provenance !== 'object') {
    return ['there is no provenance record: a candidate that is not bound to the scan that produced it cannot be accepted'];
  }
  if (provenance.kind !== PROVENANCE_KIND || provenance.schemaVersion !== PROVENANCE_SCHEMA_VERSION) {
    problems.push(`the provenance record is not a ${PROVENANCE_KIND} v${PROVENANCE_SCHEMA_VERSION} record`);
    return problems;
  }
  if (provenance.digest !== provenanceDigest(provenance)) {
    problems.push('the provenance digest does not match its contents: the record was altered');
  }
  if (provenance.candidate?.sha256 !== sha256(candidateText)) {
    problems.push('the candidate is not the file the provenance record describes (sha256 mismatch)');
  }
  let candidate = null;
  try {
    candidate = JSON.parse(candidateText);
  } catch {
    problems.push('the candidate is not valid JSON');
  }
  if (candidate && provenance.candidate?.findings !== candidate.findings?.length) {
    problems.push('the candidate finding count differs from the provenance record');
  }
  if (provenance.gate?.integrityTrusted !== true || provenance.gate?.bootstrapActive !== true) {
    problems.push('the provenance does not record a trusted bootstrap scan');
  }
  return problems;
}

// The provenance matches THIS repository's configuration. `consumer` (optional)
// adds the working-tree checks made at acceptance: HEAD, cleanliness, origin and
// the current .semgrepignore.
export function provenanceBindingProblems(provenance, config, consumer = null) {
  const problems = [];
  const p = provenance;
  const expectedRef = `refs/heads/${config.repository.defaultBranch}`;
  if (p.repository?.slug?.toLowerCase() !== config.repository.slug?.toLowerCase()) {
    problems.push(`the candidate was scanned in ${p.repository?.slug}, not ${config.repository.slug}`);
  }
  if (p.defaultBranch !== config.repository.defaultBranch) {
    problems.push(`the scan saw default branch '${p.defaultBranch}', but repository.defaultBranch is '${config.repository.defaultBranch}'`);
  }
  if (p.scan?.event !== ONBOARDING_EVENT) {
    problems.push(
      `the candidate came from a '${p.scan?.event}' run. Only a full-tree workflow_dispatch scan may supply a baseline (pull_request and push scans are diff-aware)`
    );
  }
  if (p.scan?.ref !== expectedRef) {
    problems.push(`the candidate was scanned on ${p.scan?.ref}; only the default branch (${expectedRef}) is supported for onboarding`);
  }
  if (p.framework?.repository !== config.framework.repository || p.framework?.ref !== config.framework.ref) {
    problems.push(`the scan ran framework ${p.framework?.repository}@${p.framework?.ref}, but framework.ref is ${config.framework.repository}@${config.framework.ref}`);
  }
  if (!sameList(p.semgrep?.configs, config.semgrep.rulesets)) {
    problems.push(`the scan used Semgrep configs [${(p.semgrep?.configs ?? []).join(' ')}], but semgrep.rulesets is [${config.semgrep.rulesets.join(' ')}]`);
  }
  if (!sameList(p.semgrep?.paths, config.semgrep.roots)) {
    problems.push(`the scan used Semgrep paths [${(p.semgrep?.paths ?? []).join(' ')}], but semgrep.roots is [${config.semgrep.roots.join(' ')}]`);
  }
  if (p.baselinePath !== config.semgrep.baseline.path) {
    problems.push(`the scan was for baseline path ${p.baselinePath}, not ${config.semgrep.baseline.path}`);
  }
  if (!/^[0-9a-f]{40}$/.test(p.scan?.commit ?? '')) {
    problems.push('the provenance does not record an exact scanned commit');
  }
  if (consumer) {
    if (consumer.slug && consumer.slug.toLowerCase() !== p.repository?.slug?.toLowerCase()) {
      problems.push(`this checkout's origin is ${consumer.slug}, not ${p.repository?.slug}`);
    }
    if (consumer.head !== p.scan?.commit) {
      problems.push(`HEAD is ${consumer.head}, but the candidate was scanned at ${p.scan?.commit}. Accept it from a checkout of exactly that commit (git checkout -b accept-baseline ${p.scan?.commit})`);
    }
    if (!consumer.clean) {
      problems.push('the working tree has uncommitted changes to tracked files, so HEAD is not what would be baselined');
    }
    const current = consumer.semgrepignoreSha256;
    if ((p.semgrep?.semgrepignoreSha256 ?? null) !== current) {
      problems.push(`.semgrepignore differs from the scan (${p.semgrep?.semgrepignoreSha256 ?? 'absent'} vs ${current ?? 'absent'}); the candidate reflects a different scan scope`);
    }
  }
  return problems;
}

// gh: async (args[]) -> stdout (read-only subcommands only: `api`, `run download`).
export async function prepareCandidate({ root, config, runId, gh, tmpDir, replace = false }) {
  if (!/^\d+$/.test(String(runId))) {
    throw new Error(`--run must be a numeric workflow run id (got '${runId}')`);
  }
  const state = await rolloutState(root, config);
  if (config.semgrep.baseline.state !== 'absent' || state.baseline.exists) {
    throw new Error(
      `a baseline is already ${state.baseline.exists ? `present at ${config.semgrep.baseline.path}` : 'accepted'}; bootstrap is for first onboarding only and a candidate can never replace it`
    );
  }
  if ((await exists(join(root, CANDIDATE_FILE))) && !replace) {
    throw new Error(`${CANDIDATE_FILE} already exists; review it, or pass --replace-candidate to discard it`);
  }
  const run = JSON.parse(await gh(['api', `repos/${config.repository.slug}/actions/runs/${runId}`]));
  const problems = [];
  if (run.path !== config.workflows.security) {
    problems.push(`run ${runId} is from ${run.path}, not ${config.workflows.security}`);
  }
  if (run.event !== ONBOARDING_EVENT) {
    problems.push(
      `run ${runId} was triggered by '${run.event}'. Only a full-tree workflow_dispatch scan may supply a baseline; ${run.event} scans are diff-aware or not onboarding runs`
    );
  }
  if (run.status !== 'completed') {
    problems.push(`run ${runId} has not completed (status ${run.status})`);
  }
  // A completed run is not a successful one. `failure`, `cancelled`,
  // `timed_out`, `action_required`, `stale`, `skipped` — and any conclusion a
  // future GitHub adds — mean the scan did not finish as the workflow defines
  // it, so its artifact is not a baseline of this repository. Checked BEFORE the
  // download, alongside the other run facts; every artifact-side provenance
  // check still runs afterwards.
  else if (run.conclusion !== 'success') {
    problems.push(`run ${runId} completed with conclusion '${run.conclusion}', not 'success'; only a scan that ran to completion may supply a baseline`);
  }
  if (run.head_branch !== config.repository.defaultBranch) {
    problems.push(`run ${runId} ran on '${run.head_branch}', not the default branch '${config.repository.defaultBranch}'`);
  }
  if (problems.length > 0) {
    throw new Error(`refusing this run as a baseline source:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
  }
  await gh(['run', 'download', String(runId), '--repo', config.repository.slug, '--name', 'security-gate-results', '--dir', tmpDir]);
  return installCandidate({ root, config, artifactDir: tmpDir, run });
}

// Validates a downloaded `security-gate-results` artifact against the run it
// came from and this repository's config, then installs the candidate and its
// provenance under .ssd/candidates/ — never at the baseline path.
export async function installCandidate({ root, config, artifactDir, run }) {
  const problems = [];
  const resolveFile = async (name) => {
    for (const candidate of [join(artifactDir, name), join(artifactDir, 'reports', name)]) {
      if (await exists(candidate)) {
        return candidate;
      }
    }
    return null;
  };
  if (await resolveFile('DO-NOT-BASELINE.txt')) {
    problems.push('the artifact contains DO-NOT-BASELINE.txt: a scan in that run could not be trusted');
  }
  const gatePath = await resolveFile('security-gate.json');
  const gate = gatePath ? (await readJsonFile(gatePath)).value : null;
  if (!gate) {
    problems.push('the artifact has no readable security-gate.json');
  } else {
    if (gate.integrity?.trusted !== true) {
      problems.push('the gate result does not report integrity.trusted: true');
    }
    if (gate.bootstrap?.active !== true) {
      problems.push('the gate result does not report bootstrap.active: true — this was not a bootstrap run');
    }
  }
  const candidatePath = await resolveFile('semgrep-baseline.candidate.json');
  const candidateText = candidatePath ? await readFile(candidatePath, 'utf8') : null;
  const provenancePath = await resolveFile('semgrep-baseline.candidate.provenance.json');
  const provenanceText = provenancePath ? await readFile(provenancePath, 'utf8') : null;
  let candidate = null;
  let provenance = null;
  if (!candidateText) {
    problems.push('the artifact has no semgrep-baseline.candidate.json');
  } else {
    try {
      candidate = JSON.parse(candidateText);
    } catch (error) {
      problems.push(`the candidate is not valid JSON: ${error.message}`);
    }
  }
  try {
    provenance = provenanceText ? JSON.parse(provenanceText) : null;
  } catch {
    problems.push('the provenance record is not valid JSON');
  }
  if (candidate) {
    problems.push(...validateBaselineDocument(candidate, { rulesets: config.semgrep.rulesets }).map((error) => `the candidate ${error}`));
  }
  if (candidateText) {
    problems.push(...provenanceIntegrityProblems(provenance, candidateText));
  }
  if (provenance?.kind === PROVENANCE_KIND) {
    problems.push(...provenanceBindingProblems(provenance, config));
    if (run) {
      if (String(run.id) !== String(provenance.scan?.runId)) {
        problems.push(`the provenance names run ${provenance.scan?.runId}, but the artifact came from run ${run.id}`);
      }
      if (run.head_sha !== provenance.scan?.commit) {
        problems.push(`run ${run.id} scanned ${run.head_sha}, but the provenance records ${provenance.scan?.commit}`);
      }
      if (run.event !== provenance.scan?.event) {
        problems.push(`run ${run.id} was a '${run.event}' run, but the provenance records '${provenance.scan?.event}'`);
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`refusing the candidate:\n${[...new Set(problems)].map((p) => `  - ${p}`).join('\n')}`);
  }
  await mkdir(join(root, CANDIDATE_DIR), { recursive: true });
  // A self-ignoring directory: a candidate is never meant to be committed.
  await writeFile(join(root, CANDIDATE_DIR, '.gitignore'), '*\n');
  await writeFile(join(root, CANDIDATE_FILE), candidateText);
  await writeFile(join(root, CANDIDATE_PROVENANCE), provenanceText);
  return { candidate, provenance, run };
}

// --- accept ------------------------------------------------------------------------

export function summarizeFindings(candidate) {
  const byRule = new Map();
  for (const finding of candidate.findings) {
    byRule.set(finding.checkId, (byRule.get(finding.checkId) ?? 0) + 1);
  }
  return [...byRule.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

// Every machine check runs BEFORE the human confirmation. `consumer` is the
// current checkout: { head, clean, slug, semgrepignoreSha256 }.
export async function loadCandidateForAcceptance({ root, config, consumer }) {
  if (config.semgrep.baseline.state !== 'absent') {
    throw new Error("semgrep.baseline.state is already 'accepted'; a candidate can never replace an accepted baseline");
  }
  if (await exists(join(root, config.semgrep.baseline.path))) {
    throw new Error(
      `${config.semgrep.baseline.path} already exists; refusing to overwrite a baseline. If it must be rebuilt, delete it in a reviewed pull request first`
    );
  }
  let text;
  try {
    text = await readFile(join(root, CANDIDATE_FILE), 'utf8');
  } catch {
    throw new Error(`no candidate at ${CANDIDATE_FILE}; run \`ssd-onboard baseline prepare --run <run-id>\` first`);
  }
  let candidate;
  try {
    candidate = JSON.parse(text);
  } catch (error) {
    throw new Error(`${CANDIDATE_FILE} is not valid JSON: ${error.message}`);
  }
  const provenance = (await readJsonFile(join(root, CANDIDATE_PROVENANCE))).value;
  const problems = [
    ...validateBaselineDocument(candidate, { rulesets: config.semgrep.rulesets }).map((e) => `the candidate ${e}`),
    ...provenanceIntegrityProblems(provenance, text)
  ];
  if (provenance?.kind === PROVENANCE_KIND) {
    problems.push(...provenanceBindingProblems(provenance, config, consumer));
  }
  if (problems.length > 0) {
    throw new Error(`the candidate cannot be accepted:\n${[...new Set(problems)].map((e) => `  - ${e}`).join('\n')}`);
  }
  return { candidate, text, provenance };
}

// Writes the baseline (exact candidate bytes) and returns the updated config.
// The caller has already obtained explicit confirmation.
export async function installBaseline({ root, config, text, semgrepignoreText }) {
  const target = join(root, config.semgrep.baseline.path);
  if (await exists(target)) {
    throw new Error(`${config.semgrep.baseline.path} appeared while accepting; refusing to overwrite it`);
  }
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, text, { flag: 'wx' });
  await rm(join(root, CANDIDATE_DIR), { recursive: true, force: true });
  return {
    ...config,
    semgrep: {
      ...config.semgrep,
      baseline: { ...config.semgrep.baseline, state: 'accepted', acceptedScope: scopeDigestFor(config, semgrepignoreText) }
    }
  };
}

// --- promote -------------------------------------------------------------------------

export async function promotionBlockers({ root, config }) {
  const blockers = [];
  if (config.rollout.gateMode === 'enforce') {
    blockers.push('the repository already enforces');
  }
  const state = await rolloutState(root, config);
  if (state.name !== 'baseline-accepted') {
    blockers.push(`rollout state is '${state.name}', not 'baseline-accepted'`);
    blockers.push(...state.problems);
    if (!state.baseline.exists) {
      blockers.push(`the configured Semgrep baseline ${config.semgrep.baseline.path} is required and missing`);
    }
  }
  return blockers;
}
