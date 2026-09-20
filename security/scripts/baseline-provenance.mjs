// Binds a Semgrep baseline CANDIDATE to the exact scan that produced it.
//
// A candidate baseline is a list of fingerprints. On its own it says nothing
// about which repository, commit, rules, paths or ignore file it was computed
// from — and accepting it permanently accepts every finding in it. This script
// runs in the bootstrap run, beside generate-semgrep-baseline.mjs, and writes a
// provenance record whose digest covers the candidate's bytes and every input
// that decides what Semgrep reported. ssd-onboard refuses to accept a candidate
// whose provenance does not match the repository it is being accepted into.
//
// It refuses to write provenance for a scan that could not be trusted, or for a
// run that was not a baseline bootstrap.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROVENANCE_KIND = 'ssd-semgrep-baseline-candidate-provenance';
export const PROVENANCE_SCHEMA_VERSION = 1;

const sha256 = (data) => createHash('sha256').update(data).digest('hex');

// Deterministic JSON: object keys sorted at every level.
export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// The digest covers every field except `digest` itself.
export function provenanceDigest(provenance) {
  const { digest: _ignored, ...body } = provenance;
  return sha256(canonicalJson(body));
}

export const splitList = (value) => String(value ?? '').split(/\s+/).map((item) => item.trim()).filter(Boolean);

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${name} is required to record baseline provenance`);
  }
  return value.trim();
}

export function buildProvenance({ env, candidateBytes, gate, semgrepignoreBytes }) {
  if (gate?.integrity?.trusted !== true) {
    throw new Error('refusing to record provenance: the gate result does not report integrity.trusted: true');
  }
  if (gate?.bootstrap?.active !== true) {
    throw new Error('refusing to record provenance: this run was not a baseline bootstrap');
  }
  const candidate = JSON.parse(candidateBytes.toString('utf8'));
  if (!Array.isArray(candidate.findings)) {
    throw new Error('refusing to record provenance: the candidate has no findings array');
  }
  const execution = (gate.scannerExecution?.records ?? []).find((record) => record?.scanner === 'semgrep');
  const provenance = {
    schemaVersion: PROVENANCE_SCHEMA_VERSION,
    kind: PROVENANCE_KIND,
    repository: { slug: required(env, 'CI_REPOSITORY'), id: required(env, 'CI_REPOSITORY_ID') },
    defaultBranch: required(env, 'CI_DEFAULT_BRANCH'),
    scan: {
      commit: required(env, 'CI_SHA'),
      ref: required(env, 'CI_REF'),
      event: required(env, 'CI_EVENT'),
      runId: required(env, 'CI_RUN_ID'),
      runAttempt: required(env, 'CI_RUN_ATTEMPT')
    },
    framework: { repository: required(env, 'TOOLKIT_REPOSITORY'), ref: required(env, 'TOOLKIT_REF') },
    semgrep: {
      image: execution?.image ?? null,
      version: typeof candidate.generatedBy === 'string' ? candidate.generatedBy : null,
      configs: splitList(env.SEMGREP_CONFIGS),
      paths: splitList(env.SEMGREP_PATHS),
      // null: no .semgrepignore, so Semgrep applied its built-in ignore list.
      semgrepignoreSha256: semgrepignoreBytes === null ? null : sha256(semgrepignoreBytes)
    },
    baselinePath: required(env, 'BASELINE_PATH'),
    gate: { integrityTrusted: true, bootstrapActive: true },
    candidate: { sha256: sha256(candidateBytes), findings: candidate.findings.length }
  };
  if (provenance.semgrep.configs.length === 0 || provenance.semgrep.paths.length === 0) {
    throw new Error('refusing to record provenance: Semgrep configs and paths must be known');
  }
  return { ...provenance, digest: provenanceDigest(provenance) };
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]?.replace(/^--/, '');
    if (!['candidate', 'gate', 'output', 'semgrepignore'].includes(key) || argv[index + 1] === undefined) {
      throw new Error(
        'usage: baseline-provenance.mjs --candidate <file> --gate <security-gate.json> --semgrepignore <path> --output <file>'
      );
    }
    options[key] = argv[index + 1];
  }
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  let semgrepignoreBytes = null;
  try {
    semgrepignoreBytes = await readFile(options.semgrepignore ?? '.semgrepignore');
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  const provenance = buildProvenance({
    env: process.env,
    candidateBytes: await readFile(options.candidate),
    gate: JSON.parse(await readFile(options.gate, 'utf8')),
    semgrepignoreBytes
  });
  await writeFile(options.output, `${JSON.stringify(provenance, null, 2)}\n`);
  console.error(`Recorded provenance for ${provenance.candidate.findings} candidate finding(s): ${provenance.digest}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  try {
    await main();
  } catch (error) {
    console.error(`BASELINE PROVENANCE REFUSED: ${error.message}`);
    process.exitCode = 1;
  }
}
