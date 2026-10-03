// Production wiring for the Lambda broker: AWS SDK clients (provided by the
// Lambda Node.js runtime, so nothing is bundled) and Secrets Manager secrets.
//
// Environment (set by server/break-glass/infra/deploy.sh — no secret VALUES here):
//   TABLE_NAME                    DynamoDB table
//   SLACK_CHANNEL_ID              approval channel (ci function)
//   SLACK_APPROVER_IDS_BY_REPO    {"owner/repo":["Uxxx"]} (interactions function)
//   SLACK_BOT_TOKEN_SECRET_ARN    both functions
//   SLACK_SIGNING_SECRET_ARN      interactions function only
//   GITHUB_TOKEN_SECRET_ARN       interactions function only
import { Buffer } from 'node:buffer';

import { parseApproverMapFromEnv } from '../authorize/slack-authorize.mjs';
import { createGithubClient } from '../github.mjs';
import { createSlackClient } from '../slack.mjs';
import { createBroker } from './broker.mjs';
import { createDynamoStore } from './dynamodb-store.mjs';

let sdk;
async function loadSdk() {
  sdk ??= {
    dynamodb: await import('@aws-sdk/client-dynamodb'),
    secrets: await import('@aws-sdk/client-secrets-manager'),
    lambda: await import('@aws-sdk/client-lambda')
  };
  return sdk;
}

async function readSecret(client, secrets, arn) {
  if (!arn) return undefined;
  const result = await client.send(new secrets.GetSecretValueCommand({ SecretId: arn }));
  return result.SecretString;
}

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
  const { dynamodb, secrets } = await loadSdk();
  const secretsClient = new secrets.SecretsManagerClient({});
  const [botToken, signingSecret, githubToken] = await Promise.all([
    readSecret(secretsClient, secrets, env.SLACK_BOT_TOKEN_SECRET_ARN),
    readSecret(secretsClient, secrets, env.SLACK_SIGNING_SECRET_ARN),
    readSecret(secretsClient, secrets, env.GITHUB_TOKEN_SECRET_ARN)
  ]);

  const ddb = new dynamodb.DynamoDBClient({});
  const client = { call: (operation, input) => ddb.send(new dynamodb[`${operation}Command`](input)) };

  return createBroker({
    store: createDynamoStore({ client, tableName: env.TABLE_NAME }),
    slack: createSlackClient({ botToken }),
    github: createGithubClient({ token: githubToken }),
    // Missing secret -> verifySlackSignature returns false -> every request 401.
    signingSecret,
    // Malformed or absent map -> empty map -> nobody authorized.
    approverMap: parseApproverMapFromEnv(env.SLACK_APPROVER_IDS_BY_REPO),
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
