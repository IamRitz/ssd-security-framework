// Production wiring for the Lambda broker: AWS SDK clients (provided by the
// Lambda Node.js runtime, so nothing is bundled) and Secrets Manager secrets.
//
// Environment (set by server/break-glass/infra/deploy.sh — no secret VALUES here):
//   TABLE_NAME                    DynamoDB table
//   SLACK_CHANNEL_ID              approval channel (ci function)
//   BREAK_GLASS_ENVIRONMENT       production | synthetic (interactions function): selects
//                                 /ssd/break-glass/<environment>/approvers/<repository_id>.
//                                 Missing or anything else -> nobody is authorized.
//                                 No approver map is read from the environment (neither the
//                                 name-keyed SLACK_APPROVER_IDS_BY_REPO nor the 3A
//                                 SLACK_APPROVER_IDS_BY_REPOSITORY_ID).
//   SLACK_BOT_TOKEN_SECRET_ARN    both functions
//   SLACK_SIGNING_SECRET_ARN      interactions function only
//   GITHUB_TOKEN_SECRET_ARN       interactions function only
import { Buffer } from 'node:buffer';

import { createApproverSource } from '../authorize/approvers.mjs';
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

// Slack expects its ack within 3 s; an approver lookup slower than this is
// treated as unverified (nobody authorized) rather than stalling the ack.
const APPROVER_LOOKUP_TIMEOUT_MS = 2000;

let brokerPromise;
export function getBroker(env = process.env) {
  // Cache across warm invocations; a failed cold start retries on the next call.
  brokerPromise ??= buildBroker(env).catch((error) => {
    brokerPromise = undefined;
    throw error;
  });
  return brokerPromise;
}

async function buildBroker(env) {
  const { dynamodb, secrets, ssm } = await loadSdk();
  const secretsClient = new secrets.SecretsManagerClient({});
  const [botToken, signingSecret, githubToken] = await Promise.all([
    readSecret(secretsClient, secrets, env.SLACK_BOT_TOKEN_SECRET_ARN),
    readSecret(secretsClient, secrets, env.SLACK_SIGNING_SECRET_ARN),
    readSecret(secretsClient, secrets, env.GITHUB_TOKEN_SECRET_ARN)
  ]);

  const jwks = createJwksCache();
  const ssmClient = new ssm.SSMClient({});
  const ddb = new dynamodb.DynamoDBClient({});
  const client = { call: (operation, input) => ddb.send(new dynamodb[`${operation}Command`](input)) };

  return createBroker({
    store: createDynamoStore({ client, tableName: env.TABLE_NAME }),
    slack: createSlackClient({ botToken }),
    github: createGithubClient({ token: githubToken }),
    // Missing secret -> verifySlackSignature returns false -> every request 401.
    signingSecret,
    // One SSM parameter per repository_id, read at click time; every failure
    // authorizes nobody (broker/authorize/approvers.mjs).
    approverSource: createApproverSource({
      environment: env.BREAK_GLASS_ENVIRONMENT,
      getParameter: async (name) =>
        (
          await ssmClient.send(new ssm.GetParameterCommand({ Name: name, WithDecryption: false }), {
            abortSignal: globalThis.AbortSignal.timeout(APPROVER_LOOKUP_TIMEOUT_MS)
          })
        ).Parameter
    }),
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
