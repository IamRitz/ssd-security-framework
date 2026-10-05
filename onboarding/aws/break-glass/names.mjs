// Every name and ARN of one break-glass environment (Phase 3C), derived — never
// configured. This is the resource half of the BREAK_GLASS_STACKS contract
// (stack-names.mjs): production and synthetic differ in every runtime and
// security-state resource BY CONSTRUCTION, and assertSeparated() proves it for
// any pair of derived sets before anything is rendered or verified.
//
// The broker runtime contract these names serve (broker/lambda/runtime.mjs):
//   TABLE_NAME                    the request + replay table (both functions)
//   SLACK_CHANNEL_ID              approval channel (ci function)
//   SLACK_BOT_TOKEN_SECRET_ARN    both functions
//   SLACK_SIGNING_SECRET_ARN      interactions function only
//   GITHUB_TOKEN_SECRET_ARN       interactions function only
//   BREAK_GLASS_ENVIRONMENT       interactions function: selects
//                                 /ssd/break-glass/<environment>/approvers/<repository_id>
//                                 (Phase 3B, PR #17)
import { BREAK_GLASS_ENVIRONMENTS, BREAK_GLASS_STACKS } from '../stack-names.mjs';

// Pinned runtime inputs. Changing any of them is a reviewed template change.
export const LAMBDA_RUNTIME = 'nodejs24.x';
export const LAMBDA_ARCHITECTURE = 'arm64';
export const LAMBDA_MEMORY_MB = 256;
export const LAMBDA_TIMEOUT_SECONDS = 20;
export const LOG_RETENTION_DAYS = 90;
// Reserved concurrency of the INTERACTION function (both environments). Its
// Function URL is public and Slack's HMAC is checked inside the invocation, so
// unauthenticated traffic consumes concurrency before it is rejected; the
// reservation caps what that traffic can take from the account (the CI broker
// and every other function keep their concurrency) — over the cap, requests
// are throttled before the function runs.
// Sizing — the pool is shared by two kinds of execution:
//   synchronous  Slack's POST: verify, authorize, claim, finalize, ack (< 3 s);
//                at most 2 in flight legitimately (two approvers racing)
//   asynchronous the follow-up enqueued as an Event self-invocation (Slack
//                update + audit comment); the POST does NOT wait for it, so a
//                cap can never deadlock the two. At most 2 (one per POST)
//   = 4, + 1 for a cold start (Secrets Manager reads) or the inline fallback
//   that runs when enqueue fails. Synthetic gets the same 5: the Phase 3E
//   concurrent-claim race test exercises exactly that peak.
// Under a flood: legitimate clicks are throttled too — break-glass is then
// unavailable and the BLOCK stands (fail closed). Throttled follow-ups go back
// to Lambda's async queue and are retried until MaximumEventAgeInSeconds (900 s);
// a flood longer than that drops them (the decision itself is already final in
// DynamoDB). The CI broker gets no reservation: it has no public surface (IAM
// lambda:InvokeFunction only), so unauthenticated traffic cannot reach it.
export const INTERACTIONS_RESERVED_CONCURRENCY = 5;
// Lambda keeps at least this much account concurrency unreserved: a
// reservation that would leave less is refused by Lambda, so plan blocks first.
export const MIN_UNRESERVED_CONCURRENCY = 100;
// The zip's root holds broker/ (as `git archive … broker/` lays it out); both
// functions ship the same bundle and differ by handler (broker/lambda/index.mjs).
export const HANDLERS = Object.freeze({ ci: 'broker/lambda/index.ciHandler', interactions: 'broker/lambda/index.interactionsHandler' });
// DynamoDB TTL attribute the broker writes (broker/lambda/dynamodb-store.mjs).
export const TTL_ATTRIBUTE = 'ttl';
export const TABLE_KEY = 'requestId';
// Secrets Manager appends '-' and six random characters to a secret's name in
// its ARN. IAM matches that suffix with exactly six '?', so the grant names
// exactly one secret without knowing its random suffix (a longer name never
// matches: '?' is one character, never zero or many).
export const SECRET_SUFFIX = '-??????';

export const SECRET_KEYS = Object.freeze(['slackBotToken', 'slackSigningSecret', 'githubToken']);
const SECRET_SLUGS = { slackBotToken: 'slack-bot-token', slackSigningSecret: 'slack-signing-secret', githubToken: 'github-token' };

export function assertEnvironment(environment) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
    throw new Error(`unknown break-glass environment '${environment}' (expected ${BREAK_GLASS_ENVIRONMENTS.join(' or ')})`);
  }
  return environment;
}

export const otherEnvironment = (environment) => (assertEnvironment(environment) === 'production' ? 'synthetic' : 'production');

// -> every name of one environment (no account or region needed).
export function breakGlassNames(environment) {
  assertEnvironment(environment);
  const base = `ssd-break-glass-${environment}`;
  const functions = { ci: `${base}-ci`, interactions: `${base}-interactions` };
  return Object.freeze({
    environment,
    stack: BREAK_GLASS_STACKS[environment],
    table: `${base}-requests`,
    functions: Object.freeze(functions),
    roles: Object.freeze({ ci: `${base}-ci-execution`, interactions: `${base}-interactions-execution` }),
    rolePolicies: Object.freeze({ ci: 'ssd-break-glass-ci', interactions: 'ssd-break-glass-interactions' }),
    secrets: Object.freeze(Object.fromEntries(SECRET_KEYS.map((k) => [k, `ssd/break-glass/${environment}/${SECRET_SLUGS[k]}`]))),
    logGroups: Object.freeze({ ci: `/aws/lambda/${functions.ci}`, interactions: `/aws/lambda/${functions.interactions}` }),
    // Phase 3B contract (PR #17): one String parameter per repository_id.
    approverPrefix: `/ssd/break-glass/${environment}/approvers/`
  });
}

// -> the ARNs IAM policies and verification use. `secretPatterns` are the
// '-??????' grant patterns; `secretSamples` are concrete ARNs those patterns
// match, used as simulation inputs (a real secret's suffix is not known offline).
export function breakGlassArns(environment, { partition = 'aws', account, region }) {
  const n = breakGlassNames(environment);
  const secretArn = (name, suffix) => `arn:${partition}:secretsmanager:${region}:${account}:secret:${name}${suffix}`;
  return Object.freeze({
    table: `arn:${partition}:dynamodb:${region}:${account}:table/${n.table}`,
    functions: Object.freeze({
      ci: `arn:${partition}:lambda:${region}:${account}:function:${n.functions.ci}`,
      interactions: `arn:${partition}:lambda:${region}:${account}:function:${n.functions.interactions}`
    }),
    roles: Object.freeze({ ci: `arn:${partition}:iam::${account}:role/${n.roles.ci}`, interactions: `arn:${partition}:iam::${account}:role/${n.roles.interactions}` }),
    secretPatterns: Object.freeze(Object.fromEntries(SECRET_KEYS.map((k) => [k, secretArn(n.secrets[k], SECRET_SUFFIX)]))),
    secretSamples: Object.freeze(Object.fromEntries(SECRET_KEYS.map((k) => [k, secretArn(n.secrets[k], '-AbC123')]))),
    logStreams: Object.freeze({
      ci: `arn:${partition}:logs:${region}:${account}:log-group:${n.logGroups.ci}:*`,
      interactions: `arn:${partition}:logs:${region}:${account}:log-group:${n.logGroups.interactions}:*`
    }),
    // What `aws verify` simulates the logging grants against: each log group's
    // own ARN as AWS reports it (describe-log-groups `arn`). Not a log-stream
    // ARN: IAM's simulator answers implicitDeny for CreateLogStream /
    // PutLogEvents on every log-stream ARN under a group name containing '/'
    // (all /aws/lambda/* groups), whatever the grant — observed live, Phase 3C
    // synthetic verify, 2026-10-05. Whether real writes succeed is proven only
    // when the function runs.
    logGroupProbes: Object.freeze({
      ci: `arn:${partition}:logs:${region}:${account}:log-group:${n.logGroups.ci}:*`,
      interactions: `arn:${partition}:logs:${region}:${account}:log-group:${n.logGroups.interactions}:*`
    }),
    approverParameters: `arn:${partition}:ssm:${region}:${account}:parameter${n.approverPrefix}*`,
    approverParameterSample: `arn:${partition}:ssm:${region}:${account}:parameter${n.approverPrefix}1001`,
    // Same environment, outside the approver path: never readable.
    nonApproverParameterSample: `arn:${partition}:ssm:${region}:${account}:parameter/ssd/break-glass/${environment}/not-approvers/1001`
  });
}

// Every identifier whose reuse across environments would cross the
// production/synthetic trust boundary. The code artifact is deliberately NOT
// here: sharing an immutable bundle is allowed (the runtime state is not).
export function separationIdentifiers(environment, target, { slackChannelId } = {}) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, target);
  return {
    'stack name': [n.stack],
    'DynamoDB table': [n.table, a.table],
    'CI broker function': [n.functions.ci, a.functions.ci],
    'interaction function': [n.functions.interactions, a.functions.interactions],
    'CI execution role': [n.roles.ci, a.roles.ci],
    'interaction execution role': [n.roles.interactions, a.roles.interactions],
    'Slack bot token secret': [n.secrets.slackBotToken, a.secretPatterns.slackBotToken],
    'Slack signing secret': [n.secrets.slackSigningSecret, a.secretPatterns.slackSigningSecret],
    'GitHub token secret': [n.secrets.githubToken, a.secretPatterns.githubToken],
    'log groups': [n.logGroups.ci, n.logGroups.interactions],
    'approver parameter path': [n.approverPrefix],
    ...(slackChannelId ? { 'Slack channel': [slackChannelId] } : {})
  };
}

// -> problems[]: every identifier one environment shares with the other.
// Comparison is case-insensitive (IAM role names, for one, are).
export function separationProblems(left, right) {
  const problems = [];
  const all = (ids) => new Map(Object.entries(ids).flatMap(([what, values]) => values.map((v) => [String(v).toLowerCase(), what])));
  const r = all(right);
  for (const [value, what] of all(left)) {
    if (r.has(value)) {
      problems.push(`${what} '${value}' is also the ${r.get(value)} of the other environment`);
    }
  }
  return problems;
}

// Throws when production and synthetic share any separated identifier.
export function assertSeparated(target, slackChannels = {}) {
  const problems = separationProblems(
    separationIdentifiers('production', target, { slackChannelId: slackChannels.production }),
    separationIdentifiers('synthetic', target, { slackChannelId: slackChannels.synthetic })
  );
  if (problems.length > 0) {
    throw new Error(`production and synthetic break-glass resources are not separate: ${problems.join('; ')}`);
  }
}

// Lambda reports CodeSha256 as the standard, padded base64 of the raw SHA-256
// digest of the deployment package (.zip) bytes — not hex. The operator config
// records the digest as the 64-hex `sha256sum` prints; this is the one
// conversion, used by verify for an exact comparison.
export function codeSha256Of(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('the artifact sha256 must be 64 lower-case hex characters');
  }
  return Buffer.from(hex, 'hex').toString('base64');
}
