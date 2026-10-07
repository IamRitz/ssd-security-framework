// `ssd-onboard aws verify --scope break-glass --environment <env>` (Phase 3C):
// does the DEPLOYED break-glass stack of one environment hold the boundary the
// hardened broker assumes? Read-only by construction: every call goes through
// breakGlassVerifyAws (the Phase 2 read-only table plus break-glass metadata
// reads), which has no mutating operation, no get-secret-value and no
// get-function (code). Nothing is repaired.
//
// What it proves, each as its own check (a separate fact is never folded into
// another's PASS):
//   - the stack is ssd-onboard's, tagged for THIS environment, holding exactly
//     the expected resources under the expected names;
//   - DynamoDB: key requestId (S), on-demand, TTL ENABLED on exactly `ttl`,
//     PITR, deletion protection;
//   - the CI execution role is ALLOWED dynamodb:PutItem (the OIDC replay
//     record) on THIS environment's table, and DENIED it on the other's — by
//     simulate-principal-policy, beside offline analysis of its documents;
//   - each execution role: Lambda-only trust, exactly its one inline policy,
//     no attached policy, no wildcard beyond the documented patterns, every
//     required action ALLOWED and every forbidden one DENIED (cross-environment
//     state, secrets, approvers and functions included);
//   - the functions run the configured artifact (CodeSha256 = base64 of the
//     configured sha256), with the pinned runtime, handler and environment,
//     no VPC, and their own execution roles;
//   - the CI broker has NO Function URL and NO resource policy; the
//     interaction function has exactly one Function URL (AuthType NONE) and a
//     resource policy of exactly the two URL-scoped public statements — a
//     public InvokeFunction WITHOUT the via-URL condition would let anyone send
//     the handler a non-URL event, which it treats as its own trusted
//     follow-up;
//   - production and synthetic share no runtime or security-state identifier;
//   - secrets exist as this environment's (metadata only; populated or not);
//   - the artifact object version is in a private, versioned bucket.
// Advisory (WARN, never FAIL): no reserved-concurrency cap; a secret not yet
// populated (the broker then fails closed).
import { breakGlassReadAws } from '../aws-cli.mjs';
import { accountCheck, callerIdentity, principalCheck, regionCheck, resolveRegion } from '../identity.mjs';
import { discoverRole, discoverRolePolicies, simulateProbes } from '../discover/iam-role.mjs';
import { describeError } from '../discover/result.mjs';
import { LIVE, discoverStackByName, discoverStackResources, stackTagProblems } from '../discover/stacks.mjs';
import { analyzeExecutionRole, executionProbes, trustProblems } from '../policy/break-glass.mjs';
import { BREAK_GLASS_ENVIRONMENTS, BREAK_GLASS_STACKS } from '../stack-names.mjs';
import { BREAK_GLASS_LOGICAL_IDS as L, BREAK_GLASS_RESOURCE_TYPES } from '../templates/shared-break-glass.mjs';
import { FAIL, NOT_VERIFIED, PASS, WARN, adopt, check, deniedAccessCheck, identityCheck, report, requiredAccessCheck, worst } from '../verify.mjs';
import { artifactFindings } from './artifact.mjs';
import { discoverArtifact, discoverBackups, discoverConcurrency, discoverEventInvokeConfig, discoverFunction, discoverFunctionPolicy, discoverFunctionUrl, discoverLogGroup, discoverSecret, discoverTable, discoverTimeToLive } from './discover.mjs';
import { HANDLERS, INTERACTIONS_RESERVED_CONCURRENCY, LAMBDA_ARCHITECTURE, LAMBDA_MEMORY_MB, LAMBDA_RUNTIME, LAMBDA_TIMEOUT_SECONDS, LOG_RETENTION_DAYS, SECRET_KEYS, TABLE_KEY, TTL_ATTRIBUTE, breakGlassArns, breakGlassNames, codeSha256Of, otherEnvironment, separationIdentifiers, separationProblems } from './names.mjs';

// The only AWS wrapper break-glass verification ever receives.
export const breakGlassVerifyAws = breakGlassReadAws;

export const BREAK_GLASS_SECTIONS = Object.freeze(['Identity', 'Ownership', 'Separation', 'DynamoDB', 'CI broker', 'Interaction function', 'Secrets', 'Artifact', 'CI execution role', 'Interaction execution role']);
const ROLE_SECTION = { ci: 'CI execution role', interactions: 'Interaction execution role' };
const FN_SECTION = { ci: 'CI broker', interactions: 'Interaction function' };

const fail = (kind, message) => ({ severity: FAIL, kind, message });
const nv = (kind, message) => ({ severity: NOT_VERIFIED, kind, message });
const warn = (kind, message) => ({ severity: WARN, kind, message });
const done = (c, findings, observed = [], remediation = []) => {
  const status = worst(findings);
  return { ...c, status, findings, observed, remediation: status === PASS ? [] : remediation };
};
const unreadable = (what, result) => nv(result.state === 'unverified' ? result.error.kind : 'absent', `${what} could not be read (${result.state === 'unverified' ? describeError(result) : result.code})`);

// --- pure checks ----------------------------------------------------------------------

export function stackCheck({ environment, stack, resources }) {
  const name = BREAK_GLASS_STACKS[environment];
  const c = check('bg.stack', 'Ownership', 'Stack and resources', {
    basis: 'runtime',
    why: 'a resource is ssd-onboard\'s only when its stack, the stack\'s environment tag and its logical id prove it; a name proves nothing',
    expected: [`stack ${name}, settled, tagged ssd:environment=${environment}`, `exactly: ${Object.entries(BREAK_GLASS_RESOURCE_TYPES).map(([id, t]) => `${id} (${t})`).join(', ')}`]
  });
  if (stack.state === 'absent') return done(c, [fail('not-deployed', `stack ${name} does not exist`)], [], ['Plan and apply it: `aws plan --scope break-glass` then `aws apply`.']);
  if (stack.state !== 'present') return done(c, [unreadable(`stack ${name}`, stack)]);
  const findings = [];
  const st = stack.value;
  if (!LIVE.has(st.status)) findings.push(fail('stack-unsettled', `stack ${name} is ${st.status}`));
  findings.push(...stackTagProblems(st.tags, { scope: 'break-glass', slug: null, environment }).map((m) => fail('stack-not-owned', m)));
  if (resources.state !== 'present') {
    findings.push(unreadable(`the resources of ${name}`, resources));
  } else {
    const listed = resources.value;
    for (const [id, type] of Object.entries(BREAK_GLASS_RESOURCE_TYPES)) {
      const r = listed.find((x) => x.logicalId === id);
      if (!r) findings.push(fail('resource-missing', `${name} has no ${id}`));
      else if (r.type !== type) findings.push(fail('resource-type', `${id} is ${r.type}, not ${type}`));
    }
    for (const r of listed.filter((x) => !Object.hasOwn(BREAK_GLASS_RESOURCE_TYPES, x.logicalId))) {
      findings.push(fail('unexpected-resource', `${name} holds ${r.logicalId} (${r.type}), which a break-glass stack never holds`));
    }
    const n = breakGlassNames(environment);
    const expectedPhysical = {
      [L.table]: n.table,
      [L.ciFunction]: n.functions.ci,
      [L.interactionsFunction]: n.functions.interactions,
      [L.ciRole]: n.roles.ci,
      [L.interactionsRole]: n.roles.interactions,
      [L.ciLogGroup]: n.logGroups.ci,
      [L.interactionsLogGroup]: n.logGroups.interactions
    };
    for (const [id, physical] of Object.entries(expectedPhysical)) {
      const r = listed.find((x) => x.logicalId === id);
      if (r && r.physicalId !== physical) findings.push(fail('physical-id', `${id} is ${r.physicalId}, not ${physical}`));
    }
    for (const key of SECRET_KEYS) {
      const r = listed.find((x) => x.logicalId === L[key]);
      if (r && !String(r.physicalId).includes(`:secret:${n.secrets[key]}-`)) findings.push(fail('physical-id', `${L[key]} is ${r.physicalId}, not a secret named ${n.secrets[key]}`));
    }
  }
  return done(c, findings, [`${name}: ${st.status}`]);
}

export function tableCheck({ environment, target, table, backups }) {
  const n = breakGlassNames(environment);
  const arn = breakGlassArns(environment, target).table;
  const c = check('bg.table', 'DynamoDB', 'Request and replay table', {
    why: 'requests and one-shot OIDC replay records live here; every transition is a conditional write on key requestId',
    expected: [arn, `key ${TABLE_KEY} (S, HASH) only, no index`, 'PAY_PER_REQUEST', 'deletion protection on', 'point-in-time recovery ENABLED']
  });
  if (table.state !== 'present') return done(c, [table.state === 'absent' ? fail('table-missing', `table ${n.table} does not exist`) : unreadable(`table ${n.table}`, table)]);
  const t = table.value;
  const findings = [];
  if (t.arn !== arn) findings.push(fail('table-location', `the table ARN is ${t.arn}, not ${arn}`));
  if (t.status !== 'ACTIVE') findings.push(nv('table-not-active', `the table is ${t.status}`));
  if (JSON.stringify(t.keySchema) !== JSON.stringify([{ name: TABLE_KEY, type: 'HASH' }])) findings.push(fail('table-key', `the key schema is ${JSON.stringify(t.keySchema)}, not ${TABLE_KEY} HASH only`));
  if (!(t.attributes ?? []).some((a) => a.name === TABLE_KEY && a.type === 'S')) findings.push(fail('table-key', `${TABLE_KEY} is not a String attribute`));
  if (t.indexes.length > 0) findings.push(fail('table-index', `the table has indexes (${t.indexes.join(', ')}) the broker never uses`));
  if (t.billingMode !== 'PAY_PER_REQUEST') findings.push(fail('managed-drift', `billing mode is ${t.billingMode ?? 'unreported'}, but the stack declares PAY_PER_REQUEST`));
  if (t.deletionProtection !== true) findings.push(fail('managed-drift', 'deletion protection is off, but the stack declares it on'));
  if (backups.state !== 'present') findings.push(unreadable('point-in-time recovery', backups));
  else if (backups.value.pointInTimeRecovery !== 'ENABLED') findings.push(fail('managed-drift', `point-in-time recovery is ${backups.value.pointInTimeRecovery}`));
  return done(c, findings, [`${t.name}: ${t.status}, ${t.billingMode}, key ${JSON.stringify(t.keySchema)}`], ['Bring the table back to its stack (`aws plan` then `aws apply`).']);
}

export function ttlCheck({ environment, ttl }) {
  const c = check('bg.table-ttl', 'DynamoDB', `TTL on '${TTL_ATTRIBUTE}'`, {
    why: 'replay records and decided requests carry `ttl` (epoch seconds); without TTL on exactly that attribute they are never cleaned up',
    expected: [`TimeToLiveStatus ENABLED, AttributeName ${TTL_ATTRIBUTE}`]
  });
  if (ttl.state !== 'present') return done(c, [unreadable(`TTL of ${breakGlassNames(environment).table}`, ttl)]);
  const { status, attribute } = ttl.value;
  const findings = [];
  if (status === 'ENABLED' || status === 'ENABLING') {
    if (attribute !== TTL_ATTRIBUTE) findings.push(fail('ttl-attribute', `TTL is on attribute '${attribute}', not '${TTL_ATTRIBUTE}' (the broker writes '${TTL_ATTRIBUTE}')`));
    if (status === 'ENABLING') findings.push(nv('ttl-enabling', 'TTL is still being enabled'));
  } else {
    findings.push(fail('ttl-disabled', `TTL is ${status}`));
  }
  return done(c, findings, [`${status} on '${attribute ?? '(none)'}'`], ['Restore TimeToLiveSpecification through the stack (`aws plan` then `aws apply`).']);
}

const PINNED = (role) => ({ runtime: LAMBDA_RUNTIME, handler: HANDLERS[role], architectures: [LAMBDA_ARCHITECTURE], memorySize: LAMBDA_MEMORY_MB, timeout: LAMBDA_TIMEOUT_SECONDS, packageType: 'Zip' });

// The exact environment of each function: identifiers only, every one this
// environment's own. `secretArns` are the live ARNs (from describe-secret).
export function expectedVariables(role, environment, { slackChannelId, secretArns }) {
  const n = breakGlassNames(environment);
  return role === 'ci'
    ? { TABLE_NAME: n.table, SLACK_CHANNEL_ID: slackChannelId, SLACK_BOT_TOKEN_SECRET_ARN: secretArns.slackBotToken }
    : {
        TABLE_NAME: n.table,
        BREAK_GLASS_ENVIRONMENT: environment,
        SLACK_BOT_TOKEN_SECRET_ARN: secretArns.slackBotToken,
        SLACK_SIGNING_SECRET_ARN: secretArns.slackSigningSecret,
        GITHUB_TOKEN_SECRET_ARN: secretArns.githubToken
      };
}

export function functionCheck({ role, environment, target, fn, slackChannelId, secretArns }) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, target);
  const pinned = PINNED(role);
  const c = check(`bg.${role}-function`, FN_SECTION[role], 'Function configuration', {
    why: role === 'ci' ? 'the CI broker must run as its own role, with this environment\'s table, channel and bot token only' : 'the interaction function must run as its own role, read this environment\'s approvers and secrets only',
    expected: [a.functions[role], `role ${a.roles[role]}`, `${pinned.runtime} ${pinned.architectures[0]} ${pinned.handler}`, 'no VPC, no layers', 'environment exactly as the stack declares']
  });
  if (fn.state !== 'present') return done(c, [fn.state === 'absent' ? fail('function-missing', `${n.functions[role]} does not exist`) : unreadable(n.functions[role], fn)]);
  const f = fn.value;
  const findings = [];
  if (f.arn !== a.functions[role]) findings.push(fail('function-location', `the function ARN is ${f.arn}, not ${a.functions[role]}`));
  if (f.role !== a.roles[role]) findings.push(fail('execution-role', `runs as ${f.role}, not ${a.roles[role]}`));
  for (const [key, want] of Object.entries(pinned)) {
    if (JSON.stringify(f[key]) !== JSON.stringify(want)) findings.push(fail('managed-drift', `${key} is ${JSON.stringify(f[key])}, but the stack pins ${JSON.stringify(want)}`));
  }
  if (f.vpc) findings.push(fail('managed-drift', 'the function is attached to a VPC; the stack declares none'));
  if (f.layers.length > 0) findings.push(fail('managed-drift', `the function has layers (${f.layers.join(', ')}): code outside the reviewed artifact`));
  if (Object.values(secretArns).some((v) => v === null)) {
    findings.push(nv('prerequisite-missing', 'a secret could not be read, so the secret ARNs in the environment cannot be compared'));
  } else {
    const want = expectedVariables(role, environment, { slackChannelId, secretArns });
    const keys = [...new Set([...Object.keys(want), ...Object.keys(f.variables)])].sort();
    for (const key of keys) {
      if (!Object.hasOwn(want, key)) findings.push(fail('unexpected-variable', `environment variable ${key} is set, but the stack declares no such variable`));
      else if (f.variables[key] !== want[key]) findings.push(fail('variable-mismatch', `${key} is ${f.variables[key] === undefined ? 'missing' : `'${f.variables[key]}'`}, not '${want[key]}'`));
    }
  }
  return done(c, findings, [`${f.name}: ${f.runtime} ${f.handler}, role ${f.role}`, `environment keys: ${Object.keys(f.variables).sort().join(', ') || '(none)'}`], ['Bring the function back to its stack (`aws plan` then `aws apply`).']);
}

export function codeCheck({ role, fn, artifact }) {
  const expected = codeSha256Of(artifact.sha256);
  const c = check(`bg.${role}-code`, FN_SECTION[role], 'Code is the configured artifact', {
    why: 'the function must run exactly the reviewed bundle; Lambda reports the base64 SHA-256 of the deployed .zip',
    expected: [`CodeSha256 ${expected} (= base64 of sha256 ${artifact.sha256})`]
  });
  if (fn.state !== 'present') return done(c, [nv('prerequisite-missing', 'the function could not be read')]);
  if (fn.value.codeSha256 === null) return done(c, [nv('malformed-response', 'get-function-configuration returned no CodeSha256')]);
  return done(c, fn.value.codeSha256 === expected ? [] : [fail('code-mismatch', `the deployed CodeSha256 is ${fn.value.codeSha256}, not the configured artifact's ${expected}`)], [`CodeSha256 ${fn.value.codeSha256}`], ['Re-plan and apply with the configured artifact; never update function code out of band.']);
}

export function ciExposureCheck({ url, policy }) {
  const c = check('bg.ci-exposure', 'CI broker', 'No public surface', {
    why: 'the CI broker is reachable only by IAM principals holding lambda:InvokeFunction on it (the per-repository invoker roles)',
    expected: ['no Function URL', 'no resource-based policy']
  });
  const findings = [];
  if (url.state === 'present') findings.push(fail('ci-url', `the CI broker has a Function URL (${url.value.url}, AuthType ${url.value.authType})`));
  else if (url.state === 'unverified') findings.push(unreadable('the Function URL configuration', url));
  if (policy.state === 'present') findings.push(fail('ci-resource-policy', `the CI broker has a resource-based policy with ${policy.value.statements.length} statement(s): ${policy.value.statements.map((s) => `${s.Sid ?? '?'} ${JSON.stringify(s.Principal)} ${JSON.stringify(s.Action)}`).join('; ')}`));
  else if (policy.state === 'unverified') findings.push(unreadable('the resource-based policy', policy));
  return done(c, findings, [`Function URL: ${url.state === 'present' ? 'PRESENT' : url.state}`, `resource policy: ${policy.state === 'present' ? 'PRESENT' : policy.state}`], ['Remove the URL / permission: the CI broker is never public.']);
}

const conditionValue = (statement, operator, key) => {
  const block = statement?.Condition?.[operator];
  if (!block || typeof block !== 'object') return undefined;
  const entry = Object.entries(block).find(([k]) => k.toLowerCase() === key.toLowerCase());
  return entry ? String(entry[1]).toLowerCase() : undefined;
};
const isPublic = (principal) => principal === '*' || principal?.AWS === '*';

// Exactly the two URL-scoped public statements, on this function, and nothing else.
export function interactionsExposureCheck({ environment, target, url, policy }) {
  const fnArn = breakGlassArns(environment, target).functions.interactions;
  const c = check('bg.interactions-exposure', 'Interaction function', 'Public surface is the Function URL only', {
    why: 'Slack reaches the handler through its Function URL and the HMAC signature authenticates it; any other public invoke would deliver a non-URL event, which the handler treats as its own trusted follow-up',
    expected: [`one Function URL on ${fnArn}, AuthType NONE`, 'resource policy: exactly lambda:InvokeFunctionUrl (FunctionUrlAuthType NONE) and lambda:InvokeFunction (InvokedViaFunctionUrl true), nothing else']
  });
  const findings = [];
  if (url.state !== 'present') findings.push(url.state === 'absent' ? fail('url-missing', 'the interaction function has no Function URL') : unreadable('the Function URL configuration', url));
  else {
    if (url.value.authType !== 'NONE') findings.push(fail('url-auth', `the Function URL AuthType is ${url.value.authType}; Slack cannot sign IAM requests (the architecture requires NONE + HMAC)`));
    if (url.value.functionArn && url.value.functionArn !== fnArn) findings.push(fail('url-target', `the Function URL targets ${url.value.functionArn}, not ${fnArn}`));
  }
  if (policy.state !== 'present') findings.push(policy.state === 'absent' ? fail('url-permission-missing', 'no resource policy: Slack cannot reach the Function URL') : unreadable('the resource-based policy', policy));
  else {
    const stmts = policy.value.statements;
    const urlInvoke = stmts.filter((s) => s.Effect === 'Allow' && isPublic(s.Principal) && s.Action === 'lambda:InvokeFunctionUrl' && conditionValue(s, 'StringEquals', 'lambda:FunctionUrlAuthType') === 'none');
    const viaUrl = stmts.filter((s) => s.Effect === 'Allow' && isPublic(s.Principal) && s.Action === 'lambda:InvokeFunction' && conditionValue(s, 'Bool', 'lambda:InvokedViaFunctionUrl') === 'true');
    if (urlInvoke.length !== 1) findings.push(fail('url-permission', `expected exactly one public lambda:InvokeFunctionUrl statement conditioned on FunctionUrlAuthType NONE, found ${urlInvoke.length}`));
    if (viaUrl.length !== 1) findings.push(fail('url-permission', `expected exactly one public lambda:InvokeFunction statement conditioned on InvokedViaFunctionUrl true, found ${viaUrl.length}`));
    for (const s of stmts.filter((x) => !urlInvoke.includes(x) && !viaUrl.includes(x))) {
      findings.push(fail('extra-permission', `unexpected resource-policy statement ${s.Sid ?? '?'}: ${JSON.stringify({ Effect: s.Effect, Principal: s.Principal, Action: s.Action, Condition: s.Condition ?? null })}`));
    }
    for (const s of stmts) {
      if (s.Resource !== undefined && s.Resource !== fnArn) findings.push(fail('extra-permission', `statement ${s.Sid ?? '?'} is on ${s.Resource}, not ${fnArn}`));
    }
  }
  return done(c, findings, [`Function URL: ${url.state === 'present' ? `${url.value.authType}` : url.state}`, `resource policy statements: ${policy.state === 'present' ? policy.value.statements.length : policy.state}`], ['Restore the interaction function\'s permissions through the stack; remove any other statement.']);
}

export function asyncCheck({ config }) {
  const c = check('bg.interactions-async', 'Interaction function', 'Follow-up runs at most once', {
    why: 'the deferred side effects (Slack update, audit comment) must not be retried; a retry could post a second audit comment',
    expected: ['MaximumRetryAttempts 0', 'MaximumEventAgeInSeconds 900']
  });
  if (config.state !== 'present') return done(c, [config.state === 'absent' ? fail('async-default', 'no event invoke configuration: Lambda retries async events twice by default') : unreadable('the event invoke configuration', config)]);
  const findings = [];
  if (config.value.maximumRetryAttempts !== 0) findings.push(fail('async-retries', `MaximumRetryAttempts is ${config.value.maximumRetryAttempts}`));
  if (config.value.maximumEventAgeInSeconds !== 900) findings.push(fail('managed-drift', `MaximumEventAgeInSeconds is ${config.value.maximumEventAgeInSeconds}`));
  return done(c, findings, [`retries ${config.value.maximumRetryAttempts}, max age ${config.value.maximumEventAgeInSeconds}s`]);
}

// The PUBLIC interaction function must hold exactly its deliberate reservation
// (break-glass/names.mjs explains the sizing): without it, unauthenticated
// traffic — rejected only inside the invocation — can consume the account's
// concurrency. Absent or different is a production-readiness FAIL. The CI
// broker has no public surface; a cap there is advisory.
export function concurrencyCheck({ role, concurrency }) {
  const required = role === 'interactions';
  const c = check(`bg.${role}-concurrency`, FN_SECTION[role], 'Concurrency cap', {
    required,
    why: required
      ? 'the Function URL is public and the Slack signature is checked inside the invocation: the reservation bounds what unauthenticated traffic can consume (synchronous clicks and async follow-ups share it)'
      : 'the CI broker is reachable only through IAM; a cap would bound cost, and is advisory',
    expected: [required ? `reserved concurrency exactly ${INTERACTIONS_RESERVED_CONCURRENCY}` : 'a reserved concurrency (advisory)']
  });
  if (concurrency.state !== 'present') return done(c, [{ ...unreadable('reserved concurrency', concurrency), severity: NOT_VERIFIED }]);
  const reserved = concurrency.value.reserved;
  const observed = [reserved === null ? 'none' : `reserved ${reserved}`];
  if (!required) {
    return done(c, reserved === null ? [warn('no-concurrency-cap', 'no reserved concurrency is configured: the function can scale to the account\'s unreserved limit')] : [], observed);
  }
  if (reserved === null) {
    return done(c, [fail('no-concurrency-cap', 'the public interaction function has NO reserved concurrency: unauthenticated traffic can consume the account\'s unreserved concurrency before Slack verification rejects it')], observed, ['Restore ReservedConcurrentExecutions through the stack (`aws plan` then `aws apply`).']);
  }
  return done(c, reserved === INTERACTIONS_RESERVED_CONCURRENCY ? [] : [fail('managed-drift', `reserved concurrency is ${reserved}, but the stack declares ${INTERACTIONS_RESERVED_CONCURRENCY}`)], observed, ['Restore ReservedConcurrentExecutions through the stack (`aws plan` then `aws apply`).']);
}

export function secretsCheck({ environment, target, secrets }) {
  const n = breakGlassNames(environment);
  const a = breakGlassArns(environment, target);
  const other = breakGlassNames(otherEnvironment(environment));
  const c = check('bg.secrets', 'Secrets', 'Secret containers', {
    why: 'each environment has its own Slack app and GitHub credential; a secret of the other environment must never be referenced',
    expected: SECRET_KEYS.map((k) => `${a.secretPatterns[k]} tagged ssd:environment=${environment}`)
  });
  const findings = [];
  const observed = [];
  for (const k of SECRET_KEYS) {
    const s = secrets[k];
    if (s.state !== 'present') {
      findings.push(s.state === 'absent' ? fail('secret-missing', `secret ${n.secrets[k]} does not exist`) : unreadable(`secret ${n.secrets[k]}`, s));
      continue;
    }
    const v = s.value;
    observed.push(`${v.name}: ${v.populated ? 'populated' : 'EMPTY'}`);
    const prefix = a.secretPatterns[k].slice(0, -'??????'.length);
    if (v.name !== n.secrets[k] || !v.arn.startsWith(prefix) || v.arn.length !== prefix.length + 6) findings.push(fail('secret-location', `the secret is ${v.arn}, not one matching ${a.secretPatterns[k]}`));
    if (v.arn.includes(`:secret:${other.secrets[k]}-`)) findings.push(fail('secret-cross-environment', `${v.arn} is the ${otherEnvironment(environment)} secret`));
    if (v.deletedDate) findings.push(fail('secret-deleted', `${v.name} is scheduled for deletion`));
    const tag = v.tags.find((t) => t.key === 'ssd:environment')?.value;
    if (tag !== environment) findings.push(fail('secret-environment', `${v.name} is tagged ssd:environment=${tag ?? '(none)'}, not ${environment}`));
    if (!v.populated) findings.push(warn('secret-empty', `${v.name} has no value yet: the broker fails closed until it is put (out of band, from stdin)`));
  }
  return done(c, findings, observed, ['Put the value with `aws secretsmanager put-secret-value --secret-string file:///dev/stdin`; never in argv, config or a template.']);
}

export function logGroupsCheck({ environment, groups }) {
  const n = breakGlassNames(environment);
  const c = check('bg.log-groups', 'Ownership', 'Log groups', {
    why: 'the functions log only to their own groups, which the stack creates with a fixed retention',
    expected: [`${n.logGroups.ci} and ${n.logGroups.interactions}, ${LOG_RETENTION_DAYS}-day retention`]
  });
  const findings = [];
  for (const role of ['ci', 'interactions']) {
    const g = groups[role];
    if (g.state !== 'present') findings.push(g.state === 'absent' ? fail('log-group-missing', `${n.logGroups[role]} does not exist`) : unreadable(n.logGroups[role], g));
    else if (g.value.retentionInDays !== LOG_RETENTION_DAYS) findings.push(fail('managed-drift', `${n.logGroups[role]} retention is ${g.value.retentionInDays ?? 'never expire'}`));
  }
  return done(c, findings);
}

// Production and synthetic share nothing that crosses the trust boundary:
// derived identifiers (by construction, re-checked), the configured Slack
// channels, and what the LIVE functions actually point at.
export function separationCheck({ environment, target, operator, fns, roles }) {
  const other = otherEnvironment(environment);
  const c = check('bg.separation', 'Separation', 'Production and synthetic are separate', {
    basis: 'runtime+configuration',
    why: 'a synthetic run must never reach production state, secrets, approvers or Slack, and the reverse; the immutable code artifact is the only thing they may share',
    expected: ['no shared stack, function, table, role, secret, log group, approver path or Slack channel', `live functions reference only ${environment} resources`]
  });
  const findings = [];
  const mine = separationIdentifiers(environment, target, { slackChannelId: operator.environments[environment].slackChannelId });
  const theirs = separationIdentifiers(other, target, { slackChannelId: operator.environments[other].slackChannelId });
  findings.push(...separationProblems(mine, theirs).map((m) => fail('shared-identifier', m)));
  const otherIds = new Set(Object.values(theirs).flat().map((v) => String(v).toLowerCase()));
  const o = breakGlassNames(other);
  for (const role of ['ci', 'interactions']) {
    const fn = fns[role];
    if (fn.state !== 'present') {
      findings.push(nv('prerequisite-missing', `the ${role} function could not be read`));
      continue;
    }
    if (otherIds.has(String(fn.value.role).toLowerCase()) || String(fn.value.role).toLowerCase().endsWith(`/${o.roles[role]}`)) findings.push(fail('cross-environment-role', `the ${environment} ${role} function runs as ${fn.value.role}, a ${other} role`));
    for (const [key, value] of Object.entries(fn.value.variables)) {
      const v = String(value).toLowerCase();
      if (otherIds.has(v) || Object.values(o.secrets).some((s) => v.includes(`:secret:${s.toLowerCase()}-`)) || (key === 'BREAK_GLASS_ENVIRONMENT' && value !== environment)) {
        findings.push(fail('cross-environment-reference', `the ${environment} ${role} function's ${key} references ${other}: '${value}'`));
      }
    }
  }
  const ids = ['ci', 'interactions'].map((r) => (roles[r].state === 'present' ? roles[r].value.roleId : null));
  if (ids.every(Boolean) && ids[0] === ids[1]) findings.push(fail('shared-role', 'the CI and interaction functions share one execution role'));
  return done(c, findings, [`${environment} vs ${other}: ${Object.keys(mine).length} identifier classes compared`]);
}

// An execution role: exists as exactly this ARN, Lambda-only trust, only its
// own inline policy, nothing attached.
export function roleCheck({ role, environment, target, live, policies }) {
  const n = breakGlassNames(environment);
  const arn = breakGlassArns(environment, target).roles[role];
  const c = check(`bg.${role}-role`, ROLE_SECTION[role], 'Role, trust and attachments', {
    why: 'only Lambda may assume the role, and its effective permissions must be exactly the reviewed inline policy',
    expected: [arn, 'trust: lambda.amazonaws.com sts:AssumeRole only', `inline policy ${n.rolePolicies[role]} only; no managed policy attached`]
  });
  if (live.state !== 'present') return done(c, [live.state === 'absent' ? fail('role-missing', `${arn} does not exist`) : unreadable(arn, live)]);
  const findings = [];
  if (live.value.arn !== arn) findings.push(fail('role-location', `the role is ${live.value.arn}, not ${arn}`));
  findings.push(...trustProblems(live.value.trust ?? '{}').map((m) => fail('trust', m)));
  if (policies) {
    for (const p of policies.policies) {
      if (!(p.kind === 'inline' && p.name === `inline:${n.rolePolicies[role]}`)) findings.push(fail('unmanaged-policy', `${p.kind === 'attached' ? `managed policy ${p.arn}` : `inline policy ${p.name.slice('inline:'.length)}`} is attached: the role's effective permissions are not the reviewed policy`));
    }
    if (!policies.policies.some((p) => p.name === `inline:${n.rolePolicies[role]}`)) findings.push(fail('policy-missing', `the inline policy ${n.rolePolicies[role]} is missing`));
    if (!policies.complete) findings.push(nv('policies-incomplete', `not every policy could be read: ${policies.errors.map((e) => e.message).join('; ')}`));
  }
  return done(c, findings, [`${live.value.arn}`, ...(policies ? [`policies: ${policies.policies.map((p) => p.name).join(', ') || '(none)'}`] : [])]);
}

export function policyDocumentCheck({ role, analysis }) {
  const c = check(`bg.${role}-policy-document`, ROLE_SECTION[role], 'Policy document', {
    basis: 'policy-document',
    why: 'offline analysis of the role\'s own documents: every required grant present (dynamodb:PutItem on the table, for the CI broker), no forbidden grant, no wildcard beyond the documented patterns',
    expected: ['every required action granted on exactly its resource', 'no Action/Resource "*", no other wildcard']
  });
  if (!analysis) return done(c, [nv('prerequisite-missing', 'the role\'s policies could not be read')]);
  return done(c, analysis.findings, analysis.required.map((r) => `${r.action} on ${r.resource}: ${r.decision}`));
}

// --- orchestration ------------------------------------------------------------------

// awsVerifyBreakGlass({ operator, environment, region, exec, env, deadlineMs, now }) -> report.
// Throws AwsCliError / IdentityError for a run-ending failure.
export async function awsVerifyBreakGlass({ operator, environment, region: explicitRegion = null, exec, env = process.env, deadlineMs, now }) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {
    throw Object.assign(new Error(`--environment must be production or synthetic (got '${environment}')`), { kind: 'configuration' });
  }
  const account = operator.aws.accountId;
  const resolved = resolveRegion({ explicit: explicitRegion, configured: operator.aws.region });
  const target = { scope: 'break-glass', environment, repository: null, account, region: resolved.region, regionSource: resolved.source, caller: null, awsProfile: env.AWS_PROFILE || null };
  const calls = [];
  const sections = BREAK_GLASS_SECTIONS;
  const regionC = identityCheck(regionCheck(resolved));
  if (regionC.status === FAIL) {
    return report({ target, checks: [regionC], calls, sections, skipped: 'region mismatch: AWS was not contacted' });
  }
  const aws = breakGlassVerifyAws({ region: resolved.region, exec, env, deadlineMs, now, onCall: (argv) => calls.push(argv.slice(0, argv.indexOf('--region')).join(' ')) });
  const caller = await callerIdentity(aws);
  target.caller = caller;
  const identity = [identityCheck(accountCheck(caller, account)), identityCheck(principalCheck(caller)), regionC];
  if (identity.some((c) => c.status === FAIL)) {
    return report({ target, checks: identity, calls, sections, skipped: 'identity check failed: no resource was read' });
  }
  const t = { partition: caller.partition, account, region: resolved.region };
  const n = breakGlassNames(environment);
  const cfg = operator.environments[environment];

  // Discovery (reads only).
  const stack = await discoverStackByName(aws, n.stack);
  const resources = stack.state === 'present' ? await discoverStackResources(aws, n.stack) : stack;
  const table = await discoverTable(aws, n.table);
  const ttl = await discoverTimeToLive(aws, n.table);
  const backups = await discoverBackups(aws, n.table);
  const secrets = {};
  for (const k of SECRET_KEYS) secrets[k] = await discoverSecret(aws, n.secrets[k]);
  const secretArns = Object.fromEntries(SECRET_KEYS.map((k) => [k, secrets[k].state === 'present' ? secrets[k].value.arn : null]));
  const fns = {};
  const concurrency = {};
  for (const role of ['ci', 'interactions']) {
    fns[role] = await discoverFunction(aws, n.functions[role]);
    concurrency[role] = await discoverConcurrency(aws, n.functions[role]);
  }
  const ciUrl = await discoverFunctionUrl(aws, n.functions.ci);
  const ciPolicy = await discoverFunctionPolicy(aws, n.functions.ci);
  const intUrl = await discoverFunctionUrl(aws, n.functions.interactions);
  const intPolicy = await discoverFunctionPolicy(aws, n.functions.interactions);
  const asyncConfig = await discoverEventInvokeConfig(aws, n.functions.interactions);
  const groups = { ci: await discoverLogGroup(aws, n.logGroups.ci), interactions: await discoverLogGroup(aws, n.logGroups.interactions) };
  const artifact = await discoverArtifact(aws, cfg.artifact);

  const roles = {};
  const roleChecks = [];
  for (const role of ['ci', 'interactions']) {
    const arn = breakGlassArns(environment, t).roles[role];
    const live = await discoverRole(aws, arn);
    roles[role] = live;
    const probes = executionProbes(role, environment, t);
    let policies = null;
    let analysis = null;
    let simulation = null;
    if (live.state === 'present' && live.value.arn === arn) {
      policies = await discoverRolePolicies(aws, live.value.name ?? n.roles[role]);
      analysis = analyzeExecutionRole(role, environment, t, { policies: policies.policies, complete: policies.complete });
      simulation = await simulateProbes(aws, arn, [...probes.required, ...probes.denied]);
    }
    roleChecks.push(
      roleCheck({ role, environment, target: t, live, policies }),
      policyDocumentCheck({ role, analysis }),
      requiredAccessCheck({
        id: `bg.${role}-required-access`,
        section: ROLE_SECTION[role],
        title: 'Required access',
        why: role === 'ci' ? 'the CI broker must write the replay record and pending request (dynamodb:PutItem), and read its bot token' : 'the interaction function must claim and finalize decisions, read its secrets and approvers, and invoke itself',
        simulation,
        probes: probes.required,
        remediation: ['Restore the role\'s inline policy through the stack (`aws plan` then `aws apply`).']
      }),
      deniedAccessCheck({
        id: `bg.${role}-negative-access`,
        section: ROLE_SECTION[role],
        title: 'Negative access',
        why: `the ${environment} role must not reach the ${otherEnvironment(environment)} environment, other secrets or functions, or rewrite code, tables or roles`,
        simulation,
        probes: probes.denied,
        analysis,
        remediation: ['Remove the grant that allows it; re-run verify.']
      })
    );
  }

  const art = artifactFindings(artifact, cfg.artifact);
  const checks = [
    ...identity,
    stackCheck({ environment, stack, resources }),
    logGroupsCheck({ environment, groups }),
    separationCheck({ environment, target: t, operator, fns, roles }),
    tableCheck({ environment, target: t, table, backups }),
    ttlCheck({ environment, ttl }),
    functionCheck({ role: 'ci', environment, target: t, fn: fns.ci, slackChannelId: cfg.slackChannelId, secretArns }),
    codeCheck({ role: 'ci', fn: fns.ci, artifact: cfg.artifact }),
    ciExposureCheck({ url: ciUrl, policy: ciPolicy }),
    concurrencyCheck({ role: 'ci', concurrency: concurrency.ci }),
    functionCheck({ role: 'interactions', environment, target: t, fn: fns.interactions, slackChannelId: cfg.slackChannelId, secretArns }),
    codeCheck({ role: 'interactions', fn: fns.interactions, artifact: cfg.artifact }),
    interactionsExposureCheck({ environment, target: t, url: intUrl, policy: intPolicy }),
    asyncCheck({ config: asyncConfig }),
    concurrencyCheck({ role: 'interactions', concurrency: concurrency.interactions }),
    secretsCheck({ environment, target: t, secrets }),
    adopt(check('bg.artifact', 'Artifact', 'Published artifact', { why: 'the pinned object version must exist in a private, versioned bucket', expected: [`s3://${cfg.artifact.bucket}/${cfg.artifact.key} @ ${cfg.artifact.versionId}`] }), {
      status: worst(art.findings),
      findings: art.findings,
      observed: art.observed
    }),
    ...roleChecks
  ];
  return report({ target, checks, calls, sections });
}
