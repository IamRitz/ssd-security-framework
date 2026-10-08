// Production wiring for the Lambda broker: AWS SDK clients (provided by the
// Lambda Node.js runtime, so nothing is bundled) and Secrets Manager secrets.
//
// Environment (set by the shared break-glass stack's template,
// onboarding/aws/templates/shared-break-glass.mjs — no secret VALUES here):
//   TABLE_NAME                    DynamoDB table
//   SLACK_CHANNEL_ID              approval channel (ci function)
//   BREAK_GLASS_ENVIRONMENT       production | synthetic. Selects this environment's
//                                 /ssd/break-glass/<environment>/governance/allowed-framework-shas
//                                 (both functions) and
//                                 /ssd/break-glass/<environment>/approvers/<repository_id>
//                                 (interactions function), and is the only environment
//                                 a request may carry (both; Phase 3E). Missing or
//                                 anything else -> no framework commit is allowed,
//                                 nobody is authorized and every request is refused.
//                                 No approver map is read from the environment (neither the
//                                 name-keyed SLACK_APPROVER_IDS_BY_REPO nor the 3A
//                                 SLACK_APPROVER_IDS_BY_REPOSITORY_ID).
//   SLACK_BOT_TOKEN_SECRET_ARN    both functions
//   SLACK_SIGNING_SECRET_ARN      interactions function only
//   GITHUB_TOKEN_SECRET_ARN       interactions function only
//
// SECRETS. The CI broker (role 'ci') reads its Slack token only when it posts:
// identity and framework-commit checks never read a secret, so a refused
// request touches none. A successful read is cached for the warm container; a
// failed one is not, so the next post retries it. The interaction function
// reads its secrets at start-up, as before: it must verify every Slack
// signature first, and a decision must never be finalized by a function that
// cannot then post its audit comment.
import { Buffer } from 'node:buffer';

import { createApproverSource } from '../authorize/approvers.mjs';
import { createFrameworkPolicy } from '../identity/framework-policy.mjs';
import { createJwksCache, verifyGithubOidcToken } from '../identity/github-oidc.mjs';
import { createGithubClient } from '../github.mjs';
import { createSlackClient } from '../slack.mjs';
import { createBroker } from './broker.mjs';
import { createDynamoStore } from './dynamodb-store.mjs';

let sdk;
async function loadSdk() {
  sdk ??= {
    dynamodb: await import('@aws-sdk/client-dynamodb'),
    secrets: await import('@aws-sdk/client-secrets-manager'),
    lambda: await import('@aws-sdk/client-lambda'),
    ssm: await import('@aws-sdk/client-ssm')
  };
  return sdk;
}

async function readSecret(client, secrets, arn) {
  if (!arn) return undefined;
  const result = await client.send(new secrets.GetSecretValueCommand({ SecretId: arn }));
  return result.SecretString;
}

// A secret read on first use. A value is cached; a failure (including a secret
// with no value) is not, so a later call reads again.
export function lazySecret(read) {
  let value;
  let pending;
  return async () => {
    if (value !== undefined) return value;
    pending ??= (async () => {
      const secret = await read();
      if (typeof secret !== 'string' || secret === '') throw new Error('secret has no value');
      value = secret;
      return value;
    })().finally(() => {
      pending = undefined;
    });
    return pending;
  };
}

// SSM lookups (approvers, framework policy) must answer inside Slack's 3 s ack;
// slower is treated as unverified (nothing authorized), never as a stall.
const SSM_LOOKUP_TIMEOUT_MS = 2000;

let brokerPromise;
// role: 'ci' (lazy secrets) or 'interactions' (secrets at start-up).
export function getBroker(env = process.env, { role } = {}) {
  // Cache across warm invocations; a failed cold start retries on the next call.
  brokerPromise ??= buildBroker(env, { role }).catch((error) => {
    brokerPromise = undefined;
    throw error;
  });
  return brokerPromise;
}

// `sdk`, `jwks` and `fetchImpl` are injectable for tests only.
export async function buildBroker(env, { role, sdk: injected, jwks = createJwksCache(), fetchImpl = globalThis.fetch } = {}) {
  const { dynamodb, secrets, ssm } = injected ?? (await loadSdk());
  const secretsClient = new secrets.SecretsManagerClient({});
  const read = (arn) => () => readSecret(secretsClient, secrets, arn);

  let signingSecret;
  let getBotToken;
  let getGithubToken;
  if (role === 'ci') {
    // Nothing is read now. The CI function never verifies a Slack signature.
    getBotToken = lazySecret(read(env.SLACK_BOT_TOKEN_SECRET_ARN));
    getGithubToken = lazySecret(read(env.GITHUB_TOKEN_SECRET_ARN));
  } else {
    const [botToken, signing, githubToken] = await Promise.all([
      readSecret(secretsClient, secrets, env.SLACK_BOT_TOKEN_SECRET_ARN),
      readSecret(secretsClient, secrets, env.SLACK_SIGNING_SECRET_ARN),
      readSecret(secretsClient, secrets, env.GITHUB_TOKEN_SECRET_ARN)
    ]);
    signingSecret = signing;
    getBotToken = async () => botToken;
    getGithubToken = async () => githubToken;
  }

  const ssmClient = new ssm.SSMClient({});
  const getParameter = async (name) =>
    (
      await ssmClient.send(new ssm.GetParameterCommand({ Name: name, WithDecryption: false }), {
        abortSignal: globalThis.AbortSignal.timeout(SSM_LOOKUP_TIMEOUT_MS)
      })
    ).Parameter;
  const ddb = new dynamodb.DynamoDBClient({});
  const client = { call: (operation, input) => ddb.send(new dynamodb[`${operation}Command`](input)) };

  return createBroker({
    store: createDynamoStore({ client, tableName: env.TABLE_NAME }),
    slack: createSlackClient({ getBotToken, fetchImpl }),
    github: createGithubClient({ getToken: getGithubToken, fetchImpl }),
    // Missing secret -> verifySlackSignature returns false -> every request 401.
    signingSecret,
    // One SSM parameter per repository_id, read at click time; every failure
    // authorizes nobody (broker/authorize/approvers.mjs).
    approverSource: createApproverSource({ environment: env.BREAK_GLASS_ENVIRONMENT, getParameter }),
    // This environment's allowed framework commits, read on every notify,
    // status and click; every failure allows nothing (identity/framework-policy.mjs).
    frameworkPolicy: createFrameworkPolicy({ environment: env.BREAK_GLASS_ENVIRONMENT, getParameter }),
    // Every request must be of this environment, derived by the framework from
    // its gate evidence (Phase 3E). Missing or invalid refuses every request.
    environment: env.BREAK_GLASS_ENVIRONMENT,
    // GitHub's JWKS from its fixed URL, cached per warm container.
    verifyIdentity: (token) => verifyGithubOidcToken(token, { jwks }),
    slackChannelId: env.SLACK_CHANNEL_ID
  });
}

export async function enqueueSelf(job, env = process.env) {
  const { lambda } = await loadSdk();
  const client = new lambda.LambdaClient({});
  await client.send(
    new lambda.InvokeCommand({
      FunctionName: env.AWS_LAMBDA_FUNCTION_NAME,
      InvocationType: 'Event',
      Payload: Buffer.from(JSON.stringify(job))
    })
  );
}
