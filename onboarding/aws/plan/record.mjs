// The local plan record: plan id, change-set name, the persisted-secret check
// and the plan directory .ssd/aws-plans/<plan-id>/.
//
// PLAN ID = sha256(canonicalJson(planIdInput)). The input binds everything a
// reviewer approves and nothing incidental:
//   schemaVersion, account, region, scope, stackKind, stackName,
//   changeSetType, baseStack, templateSha256, parametersSha256, tagsSha256,
//   capabilities, framework { repository, ref }, consumer repository
// baseStack is explicit either way — { state: 'absent' } or { state: 'present',
// stackId, stackStatus, lastUpdatedTime } — so the same template planned
// against another revision of the stack is a different plan. No timestamp of
// ours, random value, caller session name or hostname is an input. The
// change-set name is `ssd-plan-<plan id>`.
//
// PERSISTED DATA IS SECRET-FREE OR NOT WRITTEN. Every file is checked, as the
// exact bytes to be written, before the directory is created; a credential
// shape refuses the plan. Nothing is redacted-and-kept.
//
// THE DIRECTORY is created exclusively through the safe-path primitives (no
// '..', no symbolic link anywhere, refused if it exists), files are opened
// O_EXCL|O_NOFOLLOW, and plan.json — which carries every other file's sha256
// — is written LAST. A directory without a valid plan.json is incomplete and is
// never an applicable plan (inspectPlanDirectory).
//
// APPLY RECORDS (Phase 2C) are the only files ever added to a plan directory
// afterwards: apply-started.json (written exclusively immediately BEFORE
// execute-change-set) and apply.json (the result, written exclusively after).
// Either one present means the plan was already handed to CloudFormation; it
// is never applied again and neither file is ever overwritten. They pass the
// same persisted-secret check as the plan.
import { constants as FS } from 'node:fs';
import { lstat, mkdir, open } from 'node:fs/promises';

import { findSecretValues } from '../../lib/config.mjs';
import { PathConfinementError, assertSafeRepoPath, safeMkdir, safeWriteFile } from '../../lib/safe-path.mjs';
import { canonicalJson, sha256 } from '../templates/common.mjs';

export const PLAN_SCHEMA_VERSION = 1;
export const PLANS_DIR = '.ssd/aws-plans';
export const PLAN_ID = /^[0-9a-f]{64}$/;
export const PLAN_FILES = Object.freeze(['template.json', 'parameters.json', 'change-set.json', 'policies.json', 'plan.json']);
export const APPLY_FILES = Object.freeze(['apply-started.json', 'apply.json']);

export class PlanRecordError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'PlanRecordError';
    this.kind = kind;
  }
}

// --- plan id ----------------------------------------------------------------------

export function planIdInput({ account, region, scope, stackKind, stackName, changeSetType, baseStack, templateSha256, parametersSha256, tagsSha256, capabilities, framework, repository }) {
  if (!baseStack || (baseStack.state !== 'absent' && baseStack.state !== 'present')) {
    throw new PlanRecordError('invalid-input', 'the plan id needs an explicit base stack state');
  }
  return {
    schemaVersion: PLAN_SCHEMA_VERSION,
    account,
    region,
    scope,
    stackKind,
    stackName,
    changeSetType,
    baseStack: baseStack.state === 'absent' ? { state: 'absent' } : { state: 'present', stackId: baseStack.stackId, stackStatus: baseStack.stackStatus, lastUpdatedTime: baseStack.lastUpdatedTime ?? null },
    templateSha256,
    parametersSha256,
    tagsSha256,
    capabilities: [...capabilities],
    framework: { repository: framework.repository, ref: framework.ref },
    repository
  };
}

export const planIdOf = (input) => sha256(canonicalJson(input));
// The validated configuration a plan was created from (plan.createdFromConfigDigest).
export const configDigestOf = (config) => sha256(canonicalJson(config));
export const changeSetNameOf = (planId) => `ssd-plan-${planId}`;
export const planDirOf = (planId) => {
  if (!PLAN_ID.test(planId)) {
    throw new PlanRecordError('invalid-plan-id', `'${planId}' is not a plan id`);
  }
  return `${PLANS_DIR}/${planId}`;
};

// --- persisted-secret check -------------------------------------------------------------

// Beyond config.mjs's credential shapes (AWS key ids, Slack tokens and webhook
// URLs, GitHub tokens, PEM private keys, URLs with credentials):
const PERSISTED_SHAPES = [
  { name: 'AWS secret access key assignment', pattern: /aws_secret_access_key/i },
  { name: 'AWS session token assignment', pattern: /aws_session_token|aws_security_token/i },
  // A 40-character base64 secret access key. Pure lower-case hex (a git commit,
  // a certificate thumbprint) is not one.
  { name: 'AWS secret access key', pattern: /(?<![A-Za-z0-9/+])(?![0-9a-f]{40}(?![A-Za-z0-9/+]))[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/ },
  { name: 'JWT', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { name: 'Slack incoming-webhook URL', pattern: /hooks\.slack(?:-gov)?\.com\//i }
];
const CREDENTIAL_ENV = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN', 'AWS_CONTAINER_AUTHORIZATION_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN'];

// files: { name: text }. Throws PlanRecordError('secret-in-plan') naming the
// file and the shape — never the value.
export function assertPersistable(files, env = process.env) {
  const hits = [];
  for (const [name, text] of Object.entries(files)) {
    for (const hit of findSecretValues(text)) {
      hits.push(`${name}: looks like a ${hit.kind}`);
    }
    for (const shape of PERSISTED_SHAPES) {
      if (shape.pattern.test(text)) {
        hits.push(`${name}: looks like a ${shape.name}`);
      }
    }
    for (const variable of CREDENTIAL_ENV) {
      const value = env[variable];
      if (typeof value === 'string' && value.length >= 8 && text.includes(value)) {
        hits.push(`${name}: contains the value of ${variable}`);
      }
    }
  }
  if (hits.length > 0) {
    throw new PlanRecordError('secret-in-plan', `refusing to write plan data that looks like it holds a credential (nothing was written):\n${[...new Set(hits)].map((h) => `  - ${h}`).join('\n')}`);
  }
}

// --- the directory ----------------------------------------------------------------------

// Before ANY AWS object is created: the slot must be confinable and free.
export async function assertPlanSlotFree(root, planId) {
  const relative = planDirOf(planId);
  const target = await assertSafeRepoPath(root, relative);
  try {
    await lstat(target);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return target;
    }
    throw error;
  }
  throw new PlanRecordError('plan-exists', `${relative} already exists: a plan is never overwritten (this exact plan was already recorded, possibly incompletely)`);
}

// files: { name: text } for every name in PLAN_FILES. plan.json is written
// last; everything is checked before the directory is created. `write` is
// injectable so tests can observe the order and fail a write midway.
export async function writePlanDirectory(root, planId, files, env = process.env, { write = safeWriteFile } = {}) {
  const names = Object.keys(files);
  if (names.length !== PLAN_FILES.length || !PLAN_FILES.every((name) => names.includes(name))) {
    throw new PlanRecordError('invalid-input', `a plan directory holds exactly ${PLAN_FILES.join(', ')}`);
  }
  assertPersistable(files, env);
  const relative = planDirOf(planId);
  await safeMkdir(root, PLANS_DIR);
  const target = await assertSafeRepoPath(root, relative);
  try {
    await mkdir(target); // not recursive: EEXIST refuses
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new PlanRecordError('plan-exists', `${relative} already exists: a plan is never overwritten`);
    }
    throw error;
  }
  for (const name of PLAN_FILES) {
    await write(root, `${relative}/${name}`, files[name], { flag: 'wx', createParents: false });
  }
  return relative;
}

// Read one file of a plan directory: confined, never through a link.
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

// Is <plan-id> a complete, internally consistent plan that `aws apply` may
// consider? -> { applicable, reason, plan }
//   - plan.json must exist (it is written last) and parse;
//   - its planId must equal the directory name AND the hash of its planIdInput;
//   - every other file must exist with the sha256 plan.json records, and the
//     template / parameters / tags hashes must be the ones the plan id binds;
//   - outcome no-changes is a complete record but never applicable.
// Apply additionally cross-checks the record (apply/plan-check.mjs) and
// re-checks AWS; this is only the local half.
export async function inspectPlanDirectory(root, planId) {
  const { texts, ...result } = await readPlan(root, planId);
  return result;
}

// inspectPlanDirectory plus the exact texts whose hashes were verified, so a
// caller never re-reads (and never trusts) a file it did not hash.
// -> { applicable, reason, plan, texts: { name: text } | null }
export async function readPlan(root, planId) {
  const relative = planDirOf(planId);
  const text = await readConfined(root, `${relative}/plan.json`);
  if (text === null) {
    return { applicable: false, reason: 'incomplete: plan.json is missing (it is written last)', plan: null, texts: null };
  }
  let plan;
  try {
    plan = JSON.parse(text);
  } catch {
    return { applicable: false, reason: 'incomplete: plan.json is not valid JSON', plan: null, texts: null };
  }
  if (plan?.schemaVersion !== PLAN_SCHEMA_VERSION || plan.planId !== planId || !plan.planIdInput || planIdOf(plan.planIdInput) !== planId) {
    return { applicable: false, reason: 'inconsistent: plan.json does not bind this plan id', plan, texts: null };
  }
  const texts = { 'plan.json': text };
  for (const name of PLAN_FILES.filter((n) => n !== 'plan.json')) {
    const content = await readConfined(root, `${relative}/${name}`);
    if (content === null) {
      return { applicable: false, reason: `incomplete: ${name} is missing`, plan, texts: null };
    }
    if (sha256(content) !== plan.files?.[name]) {
      return { applicable: false, reason: `inconsistent: ${name} does not match plan.json`, plan, texts: null };
    }
    texts[name] = content;
  }
  if (plan.files['template.json'] !== plan.planIdInput.templateSha256 || plan.files['parameters.json'] !== plan.planIdInput.parametersSha256) {
    return { applicable: false, reason: 'inconsistent: the template or parameters are not the ones the plan id binds', plan, texts: null };
  }
  if (!Array.isArray(plan.tags) || sha256(canonicalJson(plan.tags)) !== plan.planIdInput.tagsSha256) {
    return { applicable: false, reason: 'inconsistent: the tags are not the ones the plan id binds', plan, texts: null };
  }
  if (plan.outcome !== 'changes') {
    return { applicable: false, reason: `outcome is ${plan.outcome}: there is nothing to apply`, plan, texts: null };
  }
  return { applicable: true, reason: null, plan, texts };
}

// --- apply records (Phase 2C) ------------------------------------------------------

// Which apply records exist for this plan. A symbolic link or anything else at
// that path counts as present: an apply record is never assumed absent.
export async function applyRecordsOf(root, planId) {
  const relative = planDirOf(planId);
  const present = [];
  for (const name of APPLY_FILES) {
    const target = await assertSafeRepoPath(root, `${relative}/${name}`);
    try {
      await lstat(target);
      present.push(name);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
  return present;
}

// Write one apply record: secret-checked, confined, exclusive (O_EXCL — an
// existing record is never overwritten), into an existing plan directory.
export async function writeApplyRecord(root, planId, name, text, env = process.env, { write = safeWriteFile } = {}) {
  if (!APPLY_FILES.includes(name)) {
    throw new PlanRecordError('invalid-input', `an apply record is one of ${APPLY_FILES.join(', ')}`);
  }
  assertPersistable({ [name]: text }, env);
  const relative = `${planDirOf(planId)}/${name}`;
  try {
    await write(root, relative, text, { flag: 'wx', createParents: false });
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new PlanRecordError('apply-record-exists', `${relative} already exists: an apply record is never overwritten`);
    }
    throw error;
  }
  return relative;
}
