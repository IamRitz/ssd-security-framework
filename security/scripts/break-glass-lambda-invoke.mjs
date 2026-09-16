// Direct Lambda invocation for the break-glass CI scripts — the transport that
// replaces the shared-secret HTTP webhooks. Credentials come from the job's
// GitHub OIDC session (aws-actions/configure-aws-credentials); no secret is
// passed, stored, or read here.
//
// Dependency-free on purpose: the gate scripts run in consumer repos with no
// node_modules of their own, so this shells out to the AWS CLI preinstalled on
// GitHub-hosted runners instead of importing the AWS SDK.
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const FUNCTION_NAME = /^[A-Za-z0-9_-]{1,64}$|^arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]{1,64}$/;

export function createLambdaInvoker({ functionName, region, execFileImpl = promisify(execFile) }) {
  if (!FUNCTION_NAME.test(functionName || '')) throw new Error('BREAK_GLASS_FUNCTION_NAME is not configured');
  if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(region || '')) throw new Error('AWS region is not configured');

  return async function invoke(event) {
    const dir = await mkdtemp(join(tmpdir(), 'break-glass-invoke-'));
    try {
      const input = join(dir, 'event.json');
      const output = join(dir, 'response.json');
      // Payload goes through a file, never argv: findings can exceed the kernel's
      // per-argument size limit.
      await writeFile(input, JSON.stringify(event), { mode: 0o600 });
      const { stdout } = await execFileImpl(
        'aws',
        [
          'lambda', 'invoke',
          '--function-name', functionName,
          '--region', region,
          '--cli-binary-format', 'raw-in-base64-out',
          '--payload', `fileb://${input}`,
          '--cli-read-timeout', '30',
          '--output', 'json',
          output
        ],
        { timeout: 45_000, maxBuffer: 1024 * 1024 }
      );
      const meta = JSON.parse(stdout);
      if (meta.StatusCode !== 200) throw new Error(`lambda invoke returned StatusCode ${meta.StatusCode}`);
      if (meta.FunctionError) throw new Error(`break-glass broker failed: ${meta.FunctionError}`);
      return JSON.parse(await readFile(output, 'utf8'));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };
}

// Returns null when the HTTP (n8n / Express) transport is selected, so both paths
// can run in parallel during the migration.
export function lambdaInvokerFromEnv(env = process.env, options = {}) {
  if ((env.BREAK_GLASS_TRANSPORT || 'http') !== 'lambda') return null;
  return createLambdaInvoker({
    functionName: env.BREAK_GLASS_FUNCTION_NAME,
    region: env.AWS_REGION || env.AWS_DEFAULT_REGION,
    ...options
  });
}
