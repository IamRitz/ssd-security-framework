import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, URL } from 'node:url';

import { lambdaInvokerFromEnv } from './break-glass-lambda-invoke.mjs';

const DEFAULT_GATE_PATH = 'reports/security-gate.json';
const DEFAULT_OUTPUT_PATH = 'reports/break-glass-request.json';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function readJson(path, label) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    throw new Error(`${label} cannot be read: ${error.message}`, { cause: error });
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`${label} is malformed JSON: ${error.message}`, { cause: error });
  }
}

export function validateEligibleGate(gate) {
  assert(gate?.verdict === 'BLOCK', 'break-glass is only available for a BLOCK verdict');
  assert(gate.breakGlass && typeof gate.breakGlass === 'object', 'gate lacks breakGlass data');
  assert(Array.isArray(gate.breakGlass.eligibleFindings), 'gate lacks eligible findings');
  assert(Array.isArray(gate.breakGlass.ineligibleFindings), 'gate lacks ineligible findings');
  assert(gate.breakGlass.eligible === true, 'BLOCK contains no overridable finding set');
  assert(gate.breakGlass.eligibleFindings.length > 0, 'eligible finding set is empty');
  assert(gate.breakGlass.ineligibleFindings.length === 0, 'hard-block findings cannot be overridden');

  for (const finding of gate.breakGlass.eligibleFindings) {
    assert(
      ['sast.critical_new', 'sast.high_new', 'dependencies.critical_with_fix',
        'dependencies.high_with_fix'].includes(finding.policyRule),
      `policy rule ${finding.policyRule} is not break-glass eligible`
    );
    assert(finding.action === 'BLOCK', 'eligible finding must be a BLOCK');
  }

  return gate.breakGlass.eligibleFindings;
}

function requireHttps(value, label) {
  assert(typeof value === 'string' && value !== '', `${label} is not configured`);
  const url = new URL(value);
  assert(url.protocol === 'https:', `${label} must use HTTPS`);
  return url;
}

export async function notifyBreakGlass({
  gate,
  endpoint,
  sharedSecret,
  context,
  timeoutSeconds = 900,
  fetchImpl = globalThis.fetch,
  // When set, the broker is invoked directly over IAM (GitHub OIDC) instead of the
  // shared-secret webhook; endpoint and sharedSecret are then unused.
  invoke = null
}) {
  const findings = validateEligibleGate(gate);
  let send;
  if (invoke) {
    send = async (payload) => {
      const result = await invoke({ action: 'notify', payload });
      assert(result?.ok === true, `break-glass broker rejected notify: ${result?.error ?? 'no response'}`);
      return result.body;
    };
  } else {
    const url = requireHttps(endpoint, 'BREAK_GLASS_NOTIFY_URL');
    assert(typeof sharedSecret === 'string' && sharedSecret !== '', 'shared secret is not configured');
    send = async (payload) => {
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-break-glass-token': sharedSecret
        },
        body: JSON.stringify(payload),
        signal: globalThis.AbortSignal.timeout(15_000)
      });
      assert(response.ok, `notification endpoint returned HTTP ${response.status}`);
      return response.json();
    };
  }
  assert(Number.isInteger(timeoutSeconds) && timeoutSeconds > 0, 'timeout must be positive');
  assert(context && typeof context === 'object', 'CI context is required');
  assert(typeof context.repository === 'string' && context.repository.includes('/'), 'repository is required');
  assert(typeof context.commitSha === 'string' && context.commitSha !== '', 'commit SHA is required');

  const gateDigest = createHash('sha256').update(JSON.stringify(gate)).digest('hex');
  const payload = {
    schemaVersion: 1,
    gateDigest,
    timeoutSeconds,
    context,
    findings
  };
  const result = await send(payload);
  assert(typeof result?.requestId === 'string' && result.requestId !== '', 'response lacks requestId');
  assert(result.status === 'pending', 'new request was not recorded as pending');
  return {
    schemaVersion: 1,
    requestId: result.requestId,
    gateDigest,
    createdAt: result.createdAt,
    expiresAt: result.expiresAt
  };
}

function parseArguments(args) {
  const options = { gate: DEFAULT_GATE_PATH, output: DEFAULT_OUTPUT_PATH, checkOnly: false };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--check-only') {
      options.checkOnly = true;
    } else if (args[index] === '--gate' || args[index] === '--output') {
      const key = args[index].slice(2);
      assert(args[index + 1], `${args[index]} requires a value`);
      options[key] = args[index + 1];
      index += 1;
    } else {
      throw new Error(`unknown argument ${args[index]}`);
    }
  }
  return options;
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const gate = await readJson(options.gate, 'security gate report');
    const findings = validateEligibleGate(gate);
    if (options.checkOnly) {
      console.log(`Break-glass eligible: ${findings.length} BLOCK finding(s)`);
      return;
    }

    const context = {
      repository: process.env.CI_REPOSITORY,
      commitSha: process.env.CI_COMMIT_SHA,
      runUrl: process.env.CI_RUN_URL,
      pullRequest: process.env.CI_PULL_REQUEST || null,
      ciSystem: process.env.CI_SYSTEM || 'unknown'
    };
    const timeoutSeconds = Number(process.env.BREAK_GLASS_TIMEOUT_SECONDS || 900);
    const result = await notifyBreakGlass({
      gate,
      endpoint: process.env.BREAK_GLASS_NOTIFY_URL,
      sharedSecret: process.env.BREAK_GLASS_SHARED_SECRET,
      context,
      timeoutSeconds,
      invoke: lambdaInvokerFromEnv(process.env)
    });
    await mkdir(dirname(options.output), { recursive: true });
    await writeFile(options.output, `${JSON.stringify(result, null, 2)}\n`);
    console.log(`Break-glass request ${result.requestId} is pending`);
  } catch (error) {
    console.error(`BREAK-GLASS: DENIED (${error.message})`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) await main();
