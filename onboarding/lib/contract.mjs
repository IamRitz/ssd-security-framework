// The generated workflows' contract with the framework at the PINNED ref.
//
// A caller that passes an input or secret the called reusable workflow does
// not declare fails to start, and a caller whose `uses:@ref` and `toolkit_ref`
// disagree runs one version's workflow against another version's scripts. Both
// are checked here, against the reusable workflow files AT framework.ref.
import { posix } from 'node:path';

import { parseYaml } from './yaml.mjs';

const LEVEL = { none: 0, read: 1, write: 2 };

// The permissions a caller job must grant for GitHub to START the called
// workflow: GitHub validates every nested job's `permissions` statically — even
// a job its `if:` would skip (docs/onboarding-architecture.md B.9) — so the
// requirement is the union over ALL of the callee's jobs.
export function requiredCallerPermissions(jobs) {
  const required = {};
  for (const job of Object.values(jobs ?? {})) {
    for (const [scope, level] of Object.entries(job?.permissions ?? {})) {
      if ((LEVEL[level] ?? 0) > (LEVEL[required[scope]] ?? 0)) {
        required[scope] = level;
      }
    }
  }
  return required;
}

// readPinned(file) -> the text of .github/workflows/<file> at framework.ref, or
// null when it cannot be read.
export async function contractProblems(rendered, config, readPinned) {
  const problems = [];
  const staticGrants = [];
  const unverified = new Set();
  const prefix = `${config.framework.repository}/.github/workflows/`;
  const pinnedCache = new Map();
  const pinned = async (file) => {
    if (!pinnedCache.has(file)) {
      const text = await readPinned(file);
      const doc = text === null ? null : parseYaml(text);
      pinnedCache.set(file, doc === null ? null : { ...(doc?.on?.workflow_call ?? {}), required: requiredCallerPermissions(doc?.jobs) });
    }
    return pinnedCache.get(file);
  };
  for (const file of rendered.filter((entry) => entry.kind === 'workflow')) {
    const doc = parseYaml(file.content);
    for (const [jobId, job] of Object.entries(doc.jobs ?? {})) {
      const where = `${file.path} job ${jobId}`;
      if (typeof job.uses === 'string' && job.uses.includes('/.github/workflows/_')) {
        const [target, ref] = job.uses.split('@');
        if (!job.uses.startsWith(prefix)) {
          problems.push(`${where} calls ${target}, not ${config.framework.repository}`);
          continue;
        }
        if (ref !== config.framework.ref) {
          problems.push(`${where} pins @${ref}, not framework.ref ${config.framework.ref}`);
        }
        const inputs = job.with ?? {};
        if (inputs.toolkit_ref !== config.framework.ref) {
          problems.push(`${where} passes toolkit_ref '${inputs.toolkit_ref}', not ${config.framework.ref}`);
        }
        if (inputs.toolkit_repository !== config.framework.repository) {
          problems.push(`${where} passes toolkit_repository '${inputs.toolkit_repository}', not ${config.framework.repository}`);
        }
        const called = posix.basename(target);
        const contract = await pinned(called);
        if (contract === null) {
          unverified.add(called);
          continue;
        }
        for (const name of Object.keys(inputs)) {
          if (!Object.hasOwn(contract.inputs ?? {}, name)) {
            problems.push(`${where} passes input '${name}', which ${called}@${config.framework.ref} does not declare — the workflow would fail to start`);
          }
        }
        for (const name of Object.keys(job.secrets ?? {})) {
          if (!Object.hasOwn(contract.secrets ?? {}, name)) {
            problems.push(`${where} passes secret '${name}', which ${called}@${config.framework.ref} does not declare — the workflow would fail to start`);
          }
        }
        for (const [name, spec] of Object.entries(contract.inputs ?? {})) {
          if (spec?.required === true && !Object.hasOwn(inputs, name)) {
            problems.push(`${where} does not pass required input '${name}' of ${called}`);
          }
        }
        // Least privilege: grant exactly what the callee statically requires —
        // less and it cannot start, more and the caller over-grants.
        const granted = job.permissions ?? {};
        const scopes = new Set([...Object.keys(granted), ...Object.keys(contract.required)]);
        for (const scope of scopes) {
          const want = contract.required[scope] ?? 'none';
          const have = granted[scope] ?? 'none';
          if (want !== have) {
            problems.push(
              `${where} grants ${scope}: ${have}, but ${called}@${config.framework.ref} statically requires ${scope}: ${want}` +
                ((LEVEL[have] ?? 0) < (LEVEL[want] ?? 0) ? ' — the workflow would fail to start' : ' — an unnecessary grant')
            );
          }
        }
        if (contract.required['id-token'] === 'write' && inputs.break_glass_enabled !== true) {
          staticGrants.push(
            `UNRESOLVED FRAMEWORK LIMITATION: ${where} grants id-token: write although break-glass is disabled, because ${called}@${config.framework.ref} declares id-token: write on a job GitHub validates statically (docs/onboarding-architecture.md B.9). The token is requested only by the break-glass step, which does not run here`
          );
        }
      }
      for (const step of job.steps ?? []) {
        if (step?.with?.repository === config.framework.repository && step.with.ref !== config.framework.ref) {
          problems.push(`${where} checks the framework out at '${step.with.ref}', not ${config.framework.ref}`);
        }
      }
    }
  }
  return { problems, staticGrants, unverified: [...unverified].sort() };
}
