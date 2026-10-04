// The ONE way ssd-onboard runs the AWS CLI.
//
// TRUST BOUNDARY. Three factories, three allowlists, no generic mutating
// wrapper:
//
//   readOnlyAws()   `aws doctor` (Phase 2A). READ-ONLY by construction: only
//                   READ_ONLY_OPERATIONS.
//   planningAws()   `aws plan` (Phase 2B). READ_ONLY_OPERATIONS plus exactly
//                   the CloudFormation calls a plan needs (PLANNING_OPERATIONS):
//                   validate-template, create-change-set (which creates an
//                   UNEXECUTED change set), describe-change-set and stack
//                   lookups by name. Nothing here can execute a change set or
//                   create, update or delete a stack or any resource.
//   applyAws()      `aws apply` (Phase 2C). Built for ONE recorded plan: its
//                   reads (applyOperations) take only that plan's exact stack
//                   name / stack id / change-set ARN, and its single mutation is
//                   aws.executeChangeSet() — a fixed argv, no caller-supplied
//                   values, at most once per wrapper. The generic call path
//                   can never reach execute-change-set or any other mutation.
//
//   - each factory refuses — BEFORE anything is executed — any argv that is
//     not an explicitly listed (service, operation) pair called with only that
//     operation's listed flags. Nothing is allowed by verb prefix, so a
//     `get-`/`list-`/`describe-` name that mutates cannot slip through, and an
//     unlisted read is refused as firmly as a write;
//   - planning flags whose VALUE matters (change-set type, capabilities, stack
//     and change-set names, tags, template body) are checked by value, so
//     IMPORT and adoption flags cannot be expressed at all;
//   - global options that change where, how or as whom a call runs
//     (--endpoint-url, --profile, --debug, --no-verify-ssl, --cli-input-json …)
//     are never accepted from a caller. The wrapper itself appends exactly
//     `--region <r> --output json --no-cli-pager`;
//   - execFile with an argv array and shell: false: repository- and
//     AWS-controlled strings are separate argv elements and never reach a shell;
//   - bounded output buffer and a deterministic timeout;
//   - credentials come only from the AWS CLI's own provider chain. Nothing here
//     reads, accepts or prints an access key; error text is reduced to the AWS
//     error code and message, with credential-shaped values and the values of
//     the credential environment variables redacted, and authentication
//     failures carry NO provider output at all (a credential_process may print
//     anything).
import { execFile } from 'node:child_process';

// The stack names ssd-onboard plans (stack-names.mjs): per repository and the
// two Phase 2 shared stacks; the two Phase 3C break-glass stacks are planned
// only through the break-glass allowlists below.
const STACK_NAMES = /^(?:ssd-delivery-[a-z0-9-]*[0-9a-f]{8}|ssd-shared-github-oidc|ssd-shared-ecr-scanning)$/;
const BREAK_GLASS_STACK_NAMES = /^ssd-break-glass-(?:production|synthetic)$/;
// Break-glass reads are confined to break-glass names: verify has no reason to
// describe any other secret, and never reads a secret VALUE (there is no
// get-secret-value anywhere in these allowlists).
const BREAK_GLASS_SECRET_ID = /^(?:arn:(?:aws|aws-cn|aws-us-gov):secretsmanager:[a-z0-9-]+:\d{12}:secret:)?ssd\/break-glass\/(?:production|synthetic)\/[a-z-]+(?:-[A-Za-z0-9]{6})?$/;
const BREAK_GLASS_FUNCTION = /^ssd-break-glass-(?:production|synthetic)-(?:ci|interactions)$/;
const BREAK_GLASS_TABLE = /^ssd-break-glass-(?:production|synthetic)-requests$/;
const BREAK_GLASS_LOG_PREFIX = /^\/aws\/lambda\/ssd-break-glass-(?:production|synthetic)-(?:ci|interactions)$/;
const is = (re) => (value) => re.test(value);

// service -> operation -> the flags it may be called with. A flag listed with
// `true` takes a value; `false` is a bare switch. Anything absent is refused.
export const READ_ONLY_OPERATIONS = Object.freeze({
  sts: {
    'get-caller-identity': {}
  },
  iam: {
    'list-open-id-connect-providers': {},
    'get-open-id-connect-provider': { '--open-id-connect-provider-arn': true },
    'get-role': { '--role-name': true },
    'list-role-policies': { '--role-name': true },
    'get-role-policy': { '--role-name': true, '--policy-name': true },
    'list-attached-role-policies': { '--role-name': true },
    'get-policy': { '--policy-arn': true },
    'get-policy-version': { '--policy-arn': true, '--version-id': true },
    'get-instance-profile': { '--instance-profile-name': true },
    'simulate-principal-policy': { '--policy-source-arn': true, '--action-names': true, '--resource-arns': true }
  },
  ecr: {
    'describe-repositories': { '--registry-id': true, '--repository-names': true },
    'get-lifecycle-policy': { '--registry-id': true, '--repository-name': true },
    'get-repository-policy': { '--registry-id': true, '--repository-name': true },
    'get-registry-scanning-configuration': {},
    'list-tags-for-resource': { '--resource-arn': true }
  },
  inspector2: {
    'batch-get-account-status': { '--account-ids': true },
    'list-coverage': { '--filter-criteria': true }
  },
  ssm: {
    'describe-instance-information': { '--filters': true }
  },
  ec2: {
    'describe-instances': { '--instance-ids': true }
  },
  cloudformation: {
    'describe-stack-resources': { '--physical-resource-id': true },
    'describe-stacks': { '--stack-name': true }
  }
});

// --- the planning allowlist (Phase 2B) ---------------------------------------------

// A planning flag is `true` (any value, as for reads) or a predicate the value
// must satisfy. Values are still refused when they look like an option or an
// AWS CLI file/URL reference.
const CHANGE_SET_NAME = /^ssd-plan-[0-9a-f]{64}$/;
// CloudFormation's limit for an inline template body.
export const MAX_TEMPLATE_BODY = 51_200;
const SSD_TAG_KEYS = new Set(['ssd:framework', 'ssd:managed-by', 'ssd:environment', 'ssd:consumer-repository']);

const matches = (re) => (value) => re.test(value);
// An inline JSON template generated by the planner: never a path or URL.
function templateBody(value) {
  if (!value.startsWith('{') || Buffer.byteLength(value, 'utf8') > MAX_TEMPLATE_BODY) {
    return false;
  }
  try {
    const parsed = JSON.parse(value);
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed);
  } catch {
    return false;
  }
}
// Stack tags: a JSON list of exactly the SSD ownership tags.
function ssdTags(value) {
  try {
    const parsed = JSON.parse(value);
    return (
      Array.isArray(parsed) &&
      parsed.length > 0 &&
      parsed.every((t) => t && typeof t === 'object' && Object.keys(t).sort().join() === 'Key,Value' && SSD_TAG_KEYS.has(t.Key) && typeof t.Value === 'string')
    );
  } catch {
    return false;
  }
}

const PLANNING_EXTRA = {
  cloudformation: {
    'describe-stack-resources': { '--physical-resource-id': true, '--stack-name': matches(STACK_NAMES) },
    'describe-stacks': { '--stack-name': true },
    'validate-template': { '--template-body': templateBody },
    // NOT listed, so refused: --template-url, --use-previous-template,
    // --role-arn, --notification-arns, --resources-to-import,
    // --import-existing-resources, --include-nested-stacks, --on-stack-failure,
    // --rollback-configuration, --parameters, --client-token, --description.
    'create-change-set': {
      '--stack-name': matches(STACK_NAMES),
      '--change-set-name': matches(CHANGE_SET_NAME),
      '--change-set-type': matches(/^(?:CREATE|UPDATE)$/),
      '--template-body': templateBody,
      '--tags': ssdTags,
      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)
    },
    'describe-change-set': { '--stack-name': matches(STACK_NAMES), '--change-set-name': matches(CHANGE_SET_NAME) }
  }
};

export const PLANNING_OPERATIONS = Object.freeze(
  Object.fromEntries(
    [...new Set([...Object.keys(READ_ONLY_OPERATIONS), ...Object.keys(PLANNING_EXTRA)])].map((service) => [
      service,
      Object.freeze({ ...(READ_ONLY_OPERATIONS[service] ?? {}), ...(PLANNING_EXTRA[service] ?? {}) })
    ])
  )
);

// --- the break-glass allowlists (Phase 3C) -----------------------------------------

// Break-glass discovery: configuration and metadata reads of the break-glass
// resources only, each confined by name. NOT added to READ_ONLY_OPERATIONS:
// doctor, the delivery plan and the delivery verify keep exactly their
// Phase 2 tables. Only `aws plan --scope break-glass` (breakGlassPlanningAws)
// and `aws verify --scope break-glass` (breakGlassReadAws) receive them.
const BREAK_GLASS_READS = {
  cloudformation: {
    'describe-stack-resources': { '--stack-name': is(BREAK_GLASS_STACK_NAMES) }
  },
  dynamodb: {
    'describe-table': { '--table-name': is(BREAK_GLASS_TABLE) },
    'describe-time-to-live': { '--table-name': is(BREAK_GLASS_TABLE) },
    'describe-continuous-backups': { '--table-name': is(BREAK_GLASS_TABLE) }
  },
  lambda: {
    // NOT get-function: its answer carries a presigned URL to the code.
    'get-function-configuration': { '--function-name': is(BREAK_GLASS_FUNCTION) },
    'get-function-url-config': { '--function-name': is(BREAK_GLASS_FUNCTION) },
    'get-policy': { '--function-name': is(BREAK_GLASS_FUNCTION) },
    'get-function-concurrency': { '--function-name': is(BREAK_GLASS_FUNCTION) },
    'get-function-event-invoke-config': { '--function-name': is(BREAK_GLASS_FUNCTION) }
  },
  secretsmanager: {
    // Metadata (name, ARN, tags, whether a version exists) — never the value.
    'describe-secret': { '--secret-id': is(BREAK_GLASS_SECRET_ID) }
  },
  logs: {
    'describe-log-groups': { '--log-group-name-prefix': is(BREAK_GLASS_LOG_PREFIX) }
  },
  s3api: {
    // The published Lambda artifact: object version metadata (never the
    // object), and the bucket's versioning and public-access posture.
    'head-object': { '--bucket': true, '--key': true, '--version-id': true, '--checksum-mode': is(/^ENABLED$/) },
    'get-bucket-versioning': { '--bucket': true },
    'get-public-access-block': { '--bucket': true },
    'get-bucket-policy-status': { '--bucket': true }
  }
};

// Union of two tables (flags of an operation listed in both are merged).
function union(a, b) {
  const out = {};
  for (const service of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const ops = {};
    for (const op of new Set([...Object.keys(a[service] ?? {}), ...Object.keys(b[service] ?? {})])) {
      ops[op] = Object.freeze({ ...(a[service]?.[op] ?? {}), ...(b[service]?.[op] ?? {}) });
    }
    out[service] = Object.freeze(ops);
  }
  return Object.freeze(out);
}

// `aws verify --scope break-glass`: the read-only table plus break-glass reads.
export const BREAK_GLASS_READ_OPERATIONS = union(READ_ONLY_OPERATIONS, BREAK_GLASS_READS);

// `aws plan --scope break-glass`: reads, plus the planning CloudFormation calls
// confined to the two break-glass stacks (never a delivery or Phase 2 shared
// stack). Like planningAws, nothing here executes a change set.
export const BREAK_GLASS_PLANNING_OPERATIONS = union(READ_ONLY_OPERATIONS, union(BREAK_GLASS_READS, {
  cloudformation: {
    'describe-stacks': { '--stack-name': true },
    'validate-template': { '--template-body': templateBody },
    'create-change-set': {
      '--stack-name': matches(BREAK_GLASS_STACK_NAMES),
      '--change-set-name': matches(CHANGE_SET_NAME),
      '--change-set-type': matches(/^(?:CREATE|UPDATE)$/),
      '--template-body': templateBody,
      '--tags': ssdTags,
      '--capabilities': matches(/^CAPABILITY_NAMED_IAM$/)
    },
    'describe-change-set': { '--stack-name': matches(BREAK_GLASS_STACK_NAMES), '--change-set-name': matches(CHANGE_SET_NAME) }
  }
}));

// --- the apply allowlist (Phase 2C) ------------------------------------------------

// Every value is the recorded plan's own: compared for equality, never matched
// by pattern. binding = { stackName, stackId, changeSetArn }.
const exactly = (...allowed) => (value) => allowed.includes(value);

const STACK_ID = /^arn:(?:aws|aws-cn|aws-us-gov):cloudformation:[a-z0-9-]+:\d{12}:stack\/([A-Za-z][A-Za-z0-9-]*)\/[0-9a-f-]+$/;
const CHANGE_SET_ARN = /^arn:(?:aws|aws-cn|aws-us-gov):cloudformation:[a-z0-9-]+:\d{12}:changeSet\/(ssd-plan-[0-9a-f]{64})\/[0-9a-f-]+$/;

function assertBinding(binding) {
  const { stackName, stackId, changeSetArn } = binding ?? {};
  const strings = [stackName, stackId, changeSetArn].every((v) => typeof v === 'string');
  if (!strings || !(STACK_NAMES.test(stackName) || BREAK_GLASS_STACK_NAMES.test(stackName)) || STACK_ID.exec(stackId)?.[1] !== stackName || !CHANGE_SET_ARN.test(changeSetArn)) {
    throw new AwsCliError('refused', "refusing to create an apply wrapper without the recorded plan's exact stack name, stack id (of that stack) and ssd-plan change-set ARN");
  }
}

// The READ operations `aws apply` may make for one plan. execute-change-set is
// deliberately absent: only applyAws().executeChangeSet() can issue it.
export function applyOperations(binding) {
  assertBinding(binding);
  const { stackName, stackId, changeSetArn } = binding;
  return Object.freeze({
    sts: Object.freeze({ 'get-caller-identity': {} }),
    cloudformation: Object.freeze({
      'describe-stacks': { '--stack-name': exactly(stackName, stackId) },
      'describe-change-set': { '--stack-name': exactly(stackName), '--change-set-name': exactly(changeSetArn) },
      'get-template': { '--stack-name': exactly(stackName), '--change-set-name': exactly(changeSetArn), '--template-stage': exactly('Original') },
      'describe-stack-resources': { '--stack-name': exactly(stackId) }
    })
  });
}

// The one mutating argv `aws apply` can produce: no other flag (no
// --role-arn, --client-request-token, --disable-rollback,
// --retain-except-on-create), no other value.
export const executeArgv = ({ stackName, changeSetArn }) => ['cloudformation', 'execute-change-set', '--stack-name', stackName, '--change-set-name', changeSetArn];

// Throws unless argv is one of the plan's reads or EXACTLY its execute argv.
// (The fake AWS harness checks every argv against this, independently.)
export function assertApply(binding) {
  const table = applyOperations(binding);
  const execute = executeArgv(binding);
  return (argv) => {
    if (Array.isArray(argv) && argv.length === execute.length && argv.every((v, i) => v === execute[i])) {
      return;
    }
    assertAllowed(argv, table, APPLY_WORDS);
  };
}

// Appended by the wrapper, so never accepted from a caller.
const WRAPPER_FLAGS = ['--region', '--output', '--no-cli-pager'];

// The AWS CLI resolves a parameter VALUE beginning with file:// or fileb:// by
// reading that local file (and, where enabled, http(s):// by fetching the URL)
// and sends the CONTENT as the parameter. Values here can come from AWS
// responses (role, policy and stack identifiers), so such indirection is
// refused for every value. No read operation opts into a scheme; a future
// command that needs one must do so per reviewed parameter, not by relaxing
// this check.
const INDIRECT_VALUE = /^(?:file|fileb|https?):\/\//i;

export const DEFAULT_TIMEOUT_MS = 60_000;
// One run's total budget across every call (L5): ~30 sequential calls must not
// be able to hold the operator for 30 × the per-call timeout.
export const DEFAULT_DEADLINE_MS = 300_000;
export const DEFAULT_MAX_BUFFER = 16 * 1024 * 1024;

// --- errors ------------------------------------------------------------------------

// kind is the machine taxonomy the doctor decides from:
//   refused              the allowlist rejected the argv; nothing was executed
//   command-unavailable  no `aws` executable
//   authentication       no/expired/invalid credentials
//   authorization        the caller is not allowed to make this call
//   not-found            AWS says the named resource does not exist
//   malformed-json       the CLI exited 0 but did not print one JSON document
//   timeout              the call did not finish in time
//   deadline             the run's overall time budget is spent (ends the run)
//   output-too-large     the CLI printed more than the buffer allows
//   aws-error            any other AWS/CLI failure (code kept when parseable)
export class AwsCliError extends Error {
  constructor(kind, message, { code = null, operation = null } = {}) {
    super(message);
    this.name = 'AwsCliError';
    this.kind = kind;
    this.code = code;
    this.operation = operation;
  }
}

// AWS error codes, by kind. Anything unlisted stays `aws-error`.
const AUTHENTICATION_CODES = new Set([
  'ExpiredToken',
  'ExpiredTokenException',
  'InvalidClientTokenId',
  'SignatureDoesNotMatch',
  'UnrecognizedClientException',
  'InvalidAccessKeyId',
  'AuthFailure',
  'RequestExpired',
  'IncompleteSignature'
]);
const AUTHORIZATION_CODES = new Set(['AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'UnauthorizedException', 'AuthorizationError']);
const NOT_FOUND_CODES = new Set([
  'NoSuchEntity',
  'RepositoryNotFoundException',
  'LifecyclePolicyNotFoundException',
  'RepositoryPolicyNotFoundException',
  'InvalidInstanceID.NotFound',
  'ResourceNotFoundException'
]);
// Local CLI messages printed before any request is made.
const NO_CREDENTIALS = [/Unable to locate credentials/i, /Error when retrieving credentials/i, /could not be found in the credentials/i, /The config profile .* could not be found/i];
// IAM Identity Center (SSO): a missing, expired or revoked session. These are
// credential failures, not AWS answers about resources (L3).
const SSO_SESSION = [
  /Error loading SSO Token/i,
  /The SSO session .* has expired/i,
  /Token has expired and refresh failed/i,
  /Unable to (?:load|refresh) (?:the )?SSO token/i,
  /SSOTokenLoadError|UnauthorizedSSOTokenError|PendingAuthorizationExpiredError/
];
// Operations of the SSO portal / OIDC services the CLI calls on the operator's
// behalf to mint credentials. Any error from them is an authentication failure.
const SSO_OPERATIONS = new Set(['GetRoleCredentials', 'CreateToken', 'ListAccounts', 'ListAccountRoles']);
const SSO_MESSAGE = 'the AWS IAM Identity Center (SSO) session is missing, expired or invalid (run `aws sso login` for this profile)';

// `An error occurred (Code) when calling the Operation operation: message`
const AWS_ERROR = /An error occurred \(([^)]{1,128})\)(?: \(reached max retries: \d+\))? when calling the (\w{1,128}) operation(?:: ([\s\S]*))?/;

// CloudFormation reports "no stack owns this physical id" as a ValidationError.
const NOT_IN_STACK = /^Stack for .* does not exist$/;

// Credential-shaped values (config.mjs refuses the same shapes in the config).
const SECRET_SHAPES = [
  /\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b/g,
  /aws_secret_access_key\s*[=:]\s*\S+/gi,
  /aws_session_token\s*[=:]\s*\S+/gi,
  /\b[A-Za-z0-9/+]{40}\b/g,
  // JWTs: web identity tokens and SSO access tokens (header.payload.signature).
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g
];
// Environment variables whose VALUES are credentials (L4). Variables that only
// name a file (AWS_WEB_IDENTITY_TOKEN_FILE, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE,
// AWS_SHARED_CREDENTIALS_FILE) hold paths, not secrets; ssd-onboard never reads
// those files — a token read from one is caught by the JWT shape above.
const CREDENTIAL_ENV = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN', 'AWS_CONTAINER_AUTHORIZATION_TOKEN'];
const MAX_MESSAGE = 500;

// Text safe to record: no credential-shaped value, no credential env value,
// bounded length. Terminal controls are the presentation layer's job.
export function redact(message, env = process.env) {
  let out = String(message ?? '');
  for (const name of CREDENTIAL_ENV) {
    const value = env[name];
    if (typeof value === 'string' && value.length >= 8) {
      out = out.split(value).join('[REDACTED]');
    }
  }
  for (const shape of SECRET_SHAPES) {
    out = out.replace(shape, '[REDACTED]');
  }
  out = out.trim();
  return out.length > MAX_MESSAGE ? `${out.slice(0, MAX_MESSAGE)}…` : out;
}

// A failed execution -> AwsCliError. `result` is { stderr, exitCode, error }.
export function classifyFailure({ stderr = '', error = null } = {}, env = process.env) {
  if (error?.code === 'ENOENT') {
    return new AwsCliError('command-unavailable', 'the `aws` command was not found on PATH (install AWS CLI v2)');
  }
  if (error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
    return new AwsCliError('output-too-large', 'the AWS CLI printed more output than ssd-onboard accepts');
  }
  if (error?.killed || error?.code === 'ETIMEDOUT') {
    return new AwsCliError('timeout', 'the AWS CLI did not finish before the timeout');
  }
  const text = String(stderr ?? '');
  const parsed = AWS_ERROR.exec(text);
  if (parsed) {
    const [, code, operation, rest = ''] = parsed;
    const message = redact(rest.split('\n')[0], env);
    if (SSO_OPERATIONS.has(operation)) {
      return new AwsCliError('authentication', SSO_MESSAGE, { code, operation });
    }
    if (AUTHENTICATION_CODES.has(code)) {
      return new AwsCliError('authentication', `AWS rejected the credentials (${code})`, { code, operation });
    }
    if (AUTHORIZATION_CODES.has(code)) {
      return new AwsCliError('authorization', message || `not authorized (${code})`, { code, operation });
    }
    if (NOT_FOUND_CODES.has(code) || (code === 'ValidationError' && NOT_IN_STACK.test(rest.trim()))) {
      return new AwsCliError('not-found', message || code, { code, operation });
    }
    return new AwsCliError('aws-error', message || code, { code, operation });
  }
  if (SSO_SESSION.some((pattern) => pattern.test(text))) {
    // Deliberately WITHOUT the CLI's text, as below.
    return new AwsCliError('authentication', SSO_MESSAGE);
  }
  if (NO_CREDENTIALS.some((pattern) => pattern.test(text))) {
    // Deliberately WITHOUT the CLI's text: it can quote provider output.
    return new AwsCliError('authentication', 'no usable AWS credentials were found by the AWS CLI provider chain');
  }
  return new AwsCliError('aws-error', redact(text.split('\n').find((line) => line.trim()) ?? 'the AWS CLI failed without an error message', env));
}

// --- the allowlist ------------------------------------------------------------------

const READ_ONLY_WORDS = { list: 'the read-only allowlist (ssd-onboard aws doctor makes no AWS changes)', kind: 'read' };
const PLANNING_WORDS = { list: 'the planning allowlist (ssd-onboard aws plan never executes a change set)', kind: 'planning' };
const APPLY_WORDS = { list: "the apply allowlist (ssd-onboard aws apply only reads the recorded plan's stack and change set, and executes nothing but that change set)", kind: 'apply' };

function assertAllowed(argv, table, words) {
  if (!Array.isArray(argv) || argv.length < 2 || !argv.every((arg) => typeof arg === 'string')) {
    throw new AwsCliError('refused', 'refusing an AWS CLI call that is not an argv array of strings');
  }
  const [service, operation, ...rest] = argv;
  const flags = Object.hasOwn(table, service) && Object.hasOwn(table[service], operation) ? table[service][operation] : null;
  if (!flags) {
    throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}': not in ${words.list}`, {
      operation: `${service} ${operation}`
    });
  }
  const seen = new Set();
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    if (!Object.hasOwn(flags, flag) || WRAPPER_FLAGS.includes(flag)) {
      throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}' with '${flag}': not an allowed parameter of this ${words.kind} operation`, {
        operation: `${service} ${operation}`
      });
    }
    if (seen.has(flag)) {
      throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}': '${flag}' given twice`, { operation: `${service} ${operation}` });
    }
    seen.add(flag);
    if (flags[flag]) {
      const value = rest[index + 1];
      // A value that looks like an option would be parsed as one by the CLI.
      if (value === undefined || value === '' || value.startsWith('-')) {
        throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}': '${flag}' needs a value that is not an option`, {
          operation: `${service} ${operation}`
        });
      }
      if (INDIRECT_VALUE.test(value)) {
        throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}': the value of '${flag}' is a file:// / fileb:// / http(s):// reference, which the AWS CLI would resolve`, {
          operation: `${service} ${operation}`
        });
      }
      if (typeof flags[flag] === 'function' && !flags[flag](value)) {
        throw new AwsCliError('refused', `refusing 'aws ${service} ${operation}': the value of '${flag}' is not one the planner may send`, {
          operation: `${service} ${operation}`
        });
      }
      index += 1;
    }
  }
}

// Throws AwsCliError('refused') unless argv is a listed read operation called
// only with its listed flags. Checked before the executor is ever reached.
export function assertReadOnly(argv) {
  assertAllowed(argv, READ_ONLY_OPERATIONS, READ_ONLY_WORDS);
}

// The same, against the planning allowlist (reads + unexecuted change sets).
export function assertPlanning(argv) {
  assertAllowed(argv, PLANNING_OPERATIONS, PLANNING_WORDS);
}

const BREAK_GLASS_READ_WORDS = { list: 'the break-glass read-only allowlist (aws verify --scope break-glass makes no AWS changes and reads no secret value)', kind: 'read' };
const BREAK_GLASS_PLANNING_WORDS = { list: 'the break-glass planning allowlist (aws plan --scope break-glass never executes a change set and uploads nothing)', kind: 'planning' };

export function assertBreakGlassRead(argv) {
  assertAllowed(argv, BREAK_GLASS_READ_OPERATIONS, BREAK_GLASS_READ_WORDS);
}

export function assertBreakGlassPlanning(argv) {
  assertAllowed(argv, BREAK_GLASS_PLANNING_OPERATIONS, BREAK_GLASS_PLANNING_WORDS);
}

// --- execution ----------------------------------------------------------------------

// The real executor: execFile, argv array, no shell. Resolves with
// { stdout, stderr, exitCode, error } and never rejects, so classification
// has one path.
export function execAws(argv, { timeoutMs = DEFAULT_TIMEOUT_MS, maxBuffer = DEFAULT_MAX_BUFFER, env = process.env } = {}) {
  return new Promise((resolvePromise) => {
    execFile(
      'aws',
      argv,
      {
        shell: false,
        timeout: timeoutMs,
        killSignal: 'SIGTERM',
        maxBuffer,
        windowsHide: true,
        env: {
          ...env,
          // Never an interactive pager or prompt; never an endpoint from config.
          AWS_PAGER: '',
          AWS_CLI_AUTO_PROMPT: 'off',
          AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: 'true'
        }
      },
      (error, stdout, stderr) => {
        resolvePromise({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), exitCode: error ? (typeof error.code === 'number' ? error.code : null) : 0, error });
      }
    );
  });
}

// readOnlyAws({ region, exec }) -> async (argv) => parsed JSON.
//   region      the resolved region; appended to every call (never the CLI default)
//   exec        injectable executor (tests); defaults to execAws
//   timeoutMs   per call
//   deadlineMs  for the whole run, measured from the wrapper's creation: each
//               call gets min(timeoutMs, remaining); once spent, every further
//               call fails with kind 'deadline', which ends the run
//   now         injectable clock (tests)
//   onCall      observer of every argv actually executed (audit/tests)
export function readOnlyAws(options = {}) {
  return wrapper(assertReadOnly, options);
}

// planningAws(options) — the same contract over the planning allowlist. Used
// only by `aws plan`; doctor never receives it.
export function planningAws(options = {}) {
  return wrapper(assertPlanning, options);
}

// Phase 3C: the break-glass wrappers, same contract over their own tables.
export function breakGlassReadAws(options = {}) {
  return wrapper(assertBreakGlassRead, options);
}

export function breakGlassPlanningAws(options = {}) {
  return wrapper(assertBreakGlassPlanning, options);
}

// applyAws({ region, binding, ...readOnlyAws options }) — the same contract
// over applyOperations(binding), plus aws.executeChangeSet(): the plan's
// execute-change-set argv, issued at most once by this wrapper. Its response
// carries no document (the CLI prints nothing), so it resolves to {}.
export function applyAws({ binding, ...options } = {}) {
  const table = applyOperations(binding);
  let executed = false;
  return wrapper((argv) => assertAllowed(argv, table, APPLY_WORDS), options, (aws, run) => {
    aws.executeChangeSet = async function executeChangeSet() {
      if (executed) {
        throw new AwsCliError('refused', 'refusing a second execute-change-set: a plan is executed at most once', { operation: 'cloudformation execute-change-set' });
      }
      executed = true;
      return run(executeArgv(binding), { allowEmpty: true });
    };
  });
}

// extend(aws, run) is the only way to reach `run` (the unchecked executor); only
// applyAws() passes one, to bind its single fixed execute argv.
function wrapper(assertCall, { region, exec = execAws, env = process.env, timeoutMs = DEFAULT_TIMEOUT_MS, deadlineMs = DEFAULT_DEADLINE_MS, now = Date.now, onCall = () => {} } = {}, extend = () => {}) {
  if (typeof region !== 'string' || region === '') {
    throw new AwsCliError('refused', 'refusing to create an AWS CLI wrapper without an explicit region');
  }
  const startedAt = now();
  const spent = (operation) => new AwsCliError('deadline', `the run's overall AWS time budget (${Math.round(deadlineMs / 1000)}s) is spent`, { operation });
  const aws = async function aws(argv) {
    assertCall(argv);
    return run(argv);
  };
  // Executes an argv the caller has already checked. Reachable only through
  // aws() above or, via `extend`, applyAws().executeChangeSet().
  async function run(argv, { allowEmpty = false } = {}) {
    const operation = `${argv[0]} ${argv[1]}`;
    const remaining = deadlineMs - (now() - startedAt);
    if (remaining <= 0) {
      throw spent(operation);
    }
    const callTimeout = Math.min(timeoutMs, remaining);
    const full = [...argv, '--region', region, '--output', 'json', '--no-cli-pager'];
    onCall(full);
    const result = await exec(full, { timeoutMs: callTimeout, env });
    if (result.error || result.exitCode !== 0) {
      const failure = classifyFailure(result, env);
      failure.operation = operation;
      // A call cut short by the remaining budget, not by its own timeout, is the deadline.
      throw failure.kind === 'timeout' && callTimeout < timeoutMs ? spent(operation) : failure;
    }
    if (allowEmpty && result.stdout.trim() === '') {
      return {};
    }
    try {
      const parsed = JSON.parse(result.stdout);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('not a JSON object');
      }
      return parsed;
    } catch {
      throw new AwsCliError('malformed-json', `'aws ${operation}' did not return a JSON object`, { operation });
    }
  }
  // Time left in the run's budget (ms), for callers that wait between calls.
  aws.remainingMs = () => deadlineMs - (now() - startedAt);
  extend(aws, run);
  return aws;
}
