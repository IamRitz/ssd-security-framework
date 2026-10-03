// `.ssd/github-plans/<plan-id>/`: the ONLY repository writes of `ssd-onboard
// github …`, and the reviewed artifact `github apply` executes.
//
//   plan.json           written by `github plan`, exclusively
//   apply-started.json  written by `github apply` immediately BEFORE its one
//                       mutation (a crash afterwards still blocks a rerun)
//   apply.json          the outcome
//
// PLAN ID = sha256(canonicalJson(planIdInput)). planIdInput binds everything
// apply must not silently re-decide: scope, repository slug, numeric id and
// default branch, the configuration digest, the framework ref, the exact
// operations (for a ruleset, the full document to POST) and the sha256 of the
// observed GitHub state they were derived from. plan.json itself is not
// trusted: apply requires planIdOf(planIdInput) to equal the directory name
// and then re-derives the plan from live state and compares.
//
// No file here ever holds a secret value: a Slack plan names the secret only.
// Every write is checked for credential shapes first (and apply also checks
// for the exact bytes it was given).
import { createHash } from 'node:crypto';
import { constants as FS } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';

import { findSecretValues } from '../lib/config.mjs';
import { PathConfinementError, assertSafeRepoPath, safeMkdir, safeWriteFile } from '../lib/safe-path.mjs';

export const PLAN_SCHEMA_VERSION = 1;
export const PLANS_DIR = '.ssd/github-plans';
export const PLAN_ID = /^[0-9a-f]{64}$/;
export const APPLY_FILES = Object.freeze(['apply-started.json', 'apply.json']);

export class PlanRecordError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'PlanRecordError';
    this.kind = kind;
  }
}

export function sortKeys(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys(value[key])])
    );
  }
  return value;
}
export const canonicalJson = (value) => `${JSON.stringify(sortKeys(value), null, 2)}\n`;
export const sha256 = (text) => createHash('sha256').update(text).digest('hex');
export const planIdOf = (input) => sha256(canonicalJson(input));
// The same digest `aws apply` binds (aws/plan/record.mjs configDigestOf).
export const configDigestOf = (config) => sha256(canonicalJson(config));

export const planDirOf = (planId) => {
  if (!PLAN_ID.test(planId)) {
    throw new PlanRecordError('invalid-plan-id', `'${planId}' is not a plan id`);
  }
  return `${PLANS_DIR}/${planId}`;
};

// --- persisted-secret check -------------------------------------------------------

const PERSISTED_SHAPES = [
  { name: 'Slack incoming-webhook URL', pattern: /hooks\.slack(?:-gov)?\.com\//i },
  { name: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}/ }
];
const CREDENTIAL_ENV = ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'];

// Throws PlanRecordError('secret-in-plan') naming the file and the shape —
// never the value. `secrets`: exact values (Buffers) that must not appear.
export function assertPersistable(name, text, { env = process.env, secrets = [] } = {}) {
  const hits = [];
  for (const hit of findSecretValues(text)) {
    hits.push(`looks like a ${hit.kind}`);
  }
  for (const shape of PERSISTED_SHAPES) {
    if (shape.pattern.test(text)) {
      hits.push(`looks like a ${shape.name}`);
    }
  }
  for (const variable of CREDENTIAL_ENV) {
    const value = env[variable];
    if (typeof value === 'string' && value.length >= 8 && text.includes(value)) {
      hits.push(`contains the value of ${variable}`);
    }
  }
  for (const secret of secrets) {
    if (Buffer.isBuffer(secret) && secret.length > 0 && Buffer.from(text, 'utf8').includes(secret)) {
      hits.push('contains the secret value being applied');
    }
  }
  if (hits.length > 0) {
    throw new PlanRecordError('secret-in-plan', `refusing to write ${name}: it ${[...new Set(hits)].join('; ')} (nothing was written)`);
  }
}

// --- reading ----------------------------------------------------------------------

async function readConfined(root, relative) {
  const target = await assertSafeRepoPath(root, relative);
  let handle;
  try {
    handle = await open(target, FS.O_RDONLY | FS.O_NOFOLLOW);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    if (error.code === 'ELOOP') {
      throw new PathConfinementError(`refusing '${relative}': it is a symbolic link`);
    }
    throw error;
  }
  try {
    return await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
}

// -> { applicable, reason, plan }. plan.json must parse, carry this schema,
// and its planId must be both the directory name and the hash of its
// planIdInput; the observed state it shows must hash to the bound digest.
export async function readPlan(root, planId) {
  const relative = planDirOf(planId);
  const text = await readConfined(root, `${relative}/plan.json`);
  if (text === null) {
    return { applicable: false, reason: `${relative}/plan.json does not exist`, plan: null };
  }
  let plan;
  try {
    plan = JSON.parse(text);
  } catch {
    return { applicable: false, reason: `${relative}/plan.json is not valid JSON`, plan: null };
  }
  if (plan?.schemaVersion !== PLAN_SCHEMA_VERSION || plan.planId !== planId || !plan.planIdInput || planIdOf(plan.planIdInput) !== planId) {
    return { applicable: false, reason: `${relative}/plan.json does not match its plan id (edited, or another schema)`, plan: null };
  }
  if (sha256(canonicalJson(plan.observed ?? null)) !== plan.planIdInput.observedSha256) {
    return { applicable: false, reason: `${relative}/plan.json: the observed state does not match the digest the plan id binds`, plan: null };
  }
  if (!Array.isArray(plan.planIdInput.operations) || plan.planIdInput.operations.length === 0) {
    return { applicable: false, reason: `${relative}/plan.json has no operations`, plan: null };
  }
  return { applicable: true, reason: null, plan };
}

export async function applyRecordsOf(root, planId) {
  const relative = planDirOf(planId);
  const found = [];
  for (const name of APPLY_FILES) {
    const target = await assertSafeRepoPath(root, `${relative}/${name}`);
    try {
      await lstat(target);
      found.push(name);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
  return found;
}

// --- writing ----------------------------------------------------------------------

// Writes plan.json exclusively. An existing slot holding byte-identical
// content is the same reviewed plan and is reused ('existing'); anything else
// is never overwritten.
export async function writePlan(root, planId, text, { env = process.env, write = safeWriteFile } = {}) {
  assertPersistable('plan.json', text, { env });
  const relative = planDirOf(planId);
  await safeMkdir(root, PLANS_DIR);
  const target = await assertSafeRepoPath(root, relative);
  try {
    await mkdir(target);
  } catch (error) {
    if (error.code !== 'EEXIST') {
      throw error;
    }
    const existing = await readConfined(root, `${relative}/plan.json`);
    if (existing === text && (await applyRecordsOf(root, planId)).length === 0) {
      return { path: relative, recorded: 'existing' };
    }
    throw new PlanRecordError('plan-exists', `${relative} already exists with other content or an apply record: a plan is never overwritten`);
  }
  await write(root, `${relative}/plan.json`, text, { flag: 'wx', createParents: false });
  return { path: relative, recorded: 'new' };
}

export async function writeApplyRecord(root, planId, name, text, { env = process.env, secrets = [], write = safeWriteFile } = {}) {
  if (!APPLY_FILES.includes(name)) {
    throw new PlanRecordError('invalid-input', `not an apply record: ${name}`);
  }
  assertPersistable(name, text, { env, secrets });
  await write(root, `${planDirOf(planId)}/${name}`, text, { flag: 'wx', createParents: false });
}
