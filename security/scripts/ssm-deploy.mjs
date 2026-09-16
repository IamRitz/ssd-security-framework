import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

// Deploys an approved image to an EC2 instance via AWS Systems Manager
// (ssm:SendCommand) instead of SSH. The instance pulls from ECR using its own
// attached read-only role; no inbound port (22 or otherwise) is required and no
// credentials leave the runner. Shared by GitHub Actions and Jenkins so both
// orchestrators run the identical remote command with different syntax — the
// same pattern as poll-ecr-scan.mjs.

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]?.replace(/^--/, '').replaceAll('-', '_');
    const value = argv[index + 1];
    assert(key && value, `incomplete argument ${argv[index]}`);
    values[key] = value;
  }
  for (const required of ['instance_id', 'region', 'registry', 'repository']) {
    assert(values[required], `missing --${required.replaceAll('_', '-')}`);
  }
  // Deploy the exact scanned+approved artifact by immutable digest when given;
  // fall back to tag otherwise.
  assert(
    values.image_digest || values.image_tag,
    'missing --image-digest (preferred) or --image-tag'
  );
  return {
    ...values,
    container_name: values.container_name ?? 'secure-software-delivery',
    app_port: values.app_port ?? '3000',
    maxAttempts: Number(values.max_attempts ?? 60),
    delaySeconds: Number(values.delay_seconds ?? 5)
  };
}

// Pull by digest (registry/repo@sha256:…) when a digest is provided — the thing
// scanned is provably the thing deployed — otherwise by tag.
export function buildImage({ registry, repository, image_tag, image_digest }) {
  return image_digest
    ? `${registry}/${repository}@${image_digest}`
    : `${registry}/${repository}:${image_tag}`;
}

// The remote shell the instance runs. `set -e` so any failed step (login, pull,
// run) surfaces as a Failed command invocation, not a false success.
export function buildDeployCommands(options) {
  const image = buildImage(options);
  return [
    'set -e',
    `aws ecr get-login-password --region ${options.region} | docker login --username AWS --password-stdin ${options.registry}`,
    `docker pull ${image}`,
    `docker rm -f ${options.container_name} 2>/dev/null || true`,
    `docker run -d --name ${options.container_name} --restart unless-stopped -p ${options.app_port}:3000 ${image}`,
    'docker image prune -f'
  ];
}

export function buildSendParameters(options) {
  return JSON.stringify({
    commands: buildDeployCommands(options),
    executionTimeout: ['600']
  });
}

// Wrap an aws-cli argument list so it runs directly on the runner (GitHub
// Actions, OIDC creds already in the env) or inside a pinned aws-cli container
// (Jenkins, static creds passed through), exactly like poll-ecr-scan.mjs.
function awsInvocation(argv, options) {
  if (!options.aws_cli_container) {
    return { command: 'aws', args: argv, environment: process.env };
  }
  return {
    command: 'docker',
    args: [
      'run', '--rm',
      '-e', 'AWS_ACCESS_KEY_ID',
      '-e', 'AWS_SECRET_ACCESS_KEY',
      '-e', 'AWS_SESSION_TOKEN',
      '-e', 'AWS_REGION',
      '-e', 'AWS_DEFAULT_REGION',
      options.aws_cli_container,
      ...argv
    ],
    environment: process.env
  };
}

export function sendCommandArgs(options) {
  return [
    'ssm', 'send-command',
    '--instance-ids', options.instance_id,
    '--document-name', 'AWS-RunShellScript',
    '--comment', `deploy ${options.image_tag}`,
    '--parameters', buildSendParameters(options),
    '--region', options.region,
    '--query', 'Command.CommandId',
    '--output', 'text'
  ];
}

export function getInvocationArgs(options, commandId) {
  return [
    'ssm', 'get-command-invocation',
    '--command-id', commandId,
    '--instance-id', options.instance_id,
    '--region', options.region,
    '--output', 'json'
  ];
}

function run({ command, args, environment }) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, { env: environment });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', (error) =>
      rejectPromise(new Error(`cannot start ${command}: ${error.message}`, { cause: error }))
    );
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

const TERMINAL = new Set(['Success', 'Failed', 'Cancelled', 'TimedOut']);

export async function deployViaSsm(options) {
  const sent = await run(awsInvocation(sendCommandArgs(options), options));
  assert(sent.code === 0, `ssm send-command failed: ${sent.stderr.trim() || `exit ${sent.code}`}`);
  const commandId = sent.stdout.trim();
  assert(commandId, 'ssm send-command returned no CommandId');
  console.log(`SSM CommandId: ${commandId}`);

  for (let attempt = 1; attempt <= options.maxAttempts; attempt += 1) {
    const result = await run(awsInvocation(getInvocationArgs(options, commandId), options));
    // Right after send, the invocation may not exist yet — treat as pending.
    if (result.code === 0) {
      const invocation = JSON.parse(result.stdout);
      const status = invocation.Status;
      console.log(`SSM invocation attempt ${attempt}/${options.maxAttempts}: ${status}`);
      if (status === 'Success') {
        if (invocation.StandardOutputContent) console.log(invocation.StandardOutputContent);
        return { commandId, status };
      }
      if (TERMINAL.has(status)) {
        throw new Error(
          `SSM deploy ended as ${status}: ${(invocation.StandardErrorContent || '').trim()}`
        );
      }
    } else {
      const stderr = result.stderr.trim();
      // Only "the invocation does not exist yet" is a legitimate transient right
      // after send-command; anything else (AccessDenied, InvalidInstanceId, ...)
      // is permanent — fail fast instead of polling for the whole window.
      const transient = /InvocationDoesNotExist/i.test(stderr);
      if (!transient || attempt === options.maxAttempts) {
        throw new Error(`ssm get-command-invocation failed: ${stderr}`);
      }
      console.log(`SSM invocation attempt ${attempt}/${options.maxAttempts}: not registered yet`);
    }
    if (attempt < options.maxAttempts) await delay(options.delaySeconds * 1000);
  }
  throw new Error('SSM deploy did not reach a terminal status before the polling limit');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  try {
    await deployViaSsm(options);
    console.log('SSM deploy succeeded');
  } catch (error) {
    // Surface the reason as a GitHub Actions annotation (a harmless log line
    // elsewhere) so it is visible without opening the full step log.
    console.log(`::error::ssm-deploy failed: ${error.message}`);
    throw error;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) await main();
