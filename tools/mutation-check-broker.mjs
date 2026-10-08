#!/usr/bin/env node
// Mutation check for the break-glass broker identity invariants (Phase 3A),
// approvers (3B), and the framework commit policy and lazy secrets (3D).
//
// Each mutation breaks exactly one property that stops one repository, run or
// workflow from acting as another; the broker and client tests must FAIL for
// every one. A surviving or stale mutation fails this script. The runner is the
// onboarding harness's (same temp-workspace lifecycle, same reporting).
//
//   node tools/mutation-check-broker.mjs
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runMutationCheck } from './mutation-check-onboarding.mjs';

export const TESTS = [
  'test/broker-oidc-identity.test.js',
  'test/broker-framework-policy.test.js',
  'test/broker-approvers-ssm.test.js',
  'test/broker-lambda.test.js',
  'test/broker-authorize.test.js',
  'test/break-glass-lambda-transport.test.js',
  'test/break-glass-ux.test.js',
  'test/break-glass-oidc-boundary.test.js',
  'test/break-glass-scenarios.test.js',
  'test/break-glass-live.test.js',
  'test/break-glass-environment.test.js'
];

const OIDC = 'broker/identity/github-oidc.mjs';
const REQUEST = 'broker/request.mjs';
const BROKER = 'broker/lambda/broker.mjs';
const STORE = 'broker/lambda/dynamodb-store.mjs';
const APPROVERS = 'broker/authorize/approvers.mjs';
const POLICY = 'broker/identity/framework-policy.mjs';
const RUNTIME = 'broker/lambda/runtime.mjs';
const LIVE = 'tools/break-glass-live.mjs';
const NOTIFY = 'security/scripts/break-glass-notify.mjs';

// authenticate(): the framework check before the replay claim (as shipped), and
// moved after it.
const AUTH_SPAN = "    // Before the token is spent: a refused commit writes nothing.\n    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);\n    if (framework.state !== 'allowed') {\n      log({ event: 'framework_rejected', action, state: framework.state, reason: framework.reason, frameworkSha: verified.jobWorkflow?.sha ?? null, ...who(verified) });\n      return { rejected: frameworkRejection(framework) };\n    }\n    const fresh = await store.consumeTokenId({\n      jtiHash: createHash('sha256').update(verified.jti).digest('hex'),\n      exp: verified.exp,\n      repositoryId: verified.repositoryId,\n      runId: verified.runId,\n      runAttempt: verified.runAttempt,\n      action\n    });\n    if (!fresh) {\n      log({ event: 'identity_rejected', action, code: 'token_replayed', ...who(verified) });\n      return { rejected: { ok: false, statusCode: 401, error: 'identity_rejected: token_replayed' } };\n    }\n";
const AUTH_MOVED = "    const fresh = await store.consumeTokenId({\n      jtiHash: createHash('sha256').update(verified.jti).digest('hex'),\n      exp: verified.exp,\n      repositoryId: verified.repositoryId,\n      runId: verified.runId,\n      runAttempt: verified.runAttempt,\n      action\n    });\n    if (!fresh) {\n      log({ event: 'identity_rejected', action, code: 'token_replayed', ...who(verified) });\n      return { rejected: { ok: false, statusCode: 401, error: 'identity_rejected: token_replayed' } };\n    }\n    // Before the token is spent: a refused commit writes nothing.\n    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);\n    if (framework.state !== 'allowed') {\n      log({ event: 'framework_rejected', action, state: framework.state, reason: framework.reason, frameworkSha: verified.jobWorkflow?.sha ?? null, ...who(verified) });\n      return { rejected: frameworkRejection(framework) };\n    }\n";

// The click path, revoke check first (as shipped) and moved after the claim.
const CLICK_SPAN = "    // Decided only for an authorized approver, and BEFORE any claim: a request\n    // whose commit is no longer allowed is not decided and changes no state.\n    if (framework.state !== 'allowed') {\n      log({\n        event: 'framework_revoked',\n        requestId: decision.requestId,\n        repositoryId,\n        userId: auth.userId,\n        state: framework.state,\n        reason: framework.reason,\n        frameworkSha: stored?.identity?.jobWorkflowSha ?? null\n      });\n      return reply('revoked', 'This request was filed by a framework commit that is no longer allowed. It cannot be decided.', {\n        requestId: decision.requestId\n      });\n    }\n\n    const nowDate = now();\n    const claim = claimDecision({\n      requestId: decision.requestId,\n      action: decision.action,\n      userId: auth.userId,\n      username: auth.username,\n      requests: { [decision.requestId]: stored },\n      now: nowDate\n    });\n    if (claim.outcome === 'expired') {\n      await store.expire(stored, nowDate.toISOString());\n      return reply('expired', 'This approval request has expired.', { requestId: decision.requestId });\n    }\n    if (claim.outcome === 'duplicate') {\n      return reply('duplicate', `This request is already ${claim.status}.`, { requestId: decision.requestId });\n    }\n    if (claim.outcome !== 'claimed') {\n      return reply('rejected', 'Unknown or invalid approval request.', { requestId: decision.requestId });\n    }\n\n    try {\n      await store.claim(claim.request, nowDate.toISOString());\n    } catch (error) {\n      if (!(error instanceof ConditionFailed)) throw error;\n      // Someone else committed first (or it expired between read and write).\n      const fresh = await store.get(decision.requestId);\n      log({ event: 'claim_lost', requestId: decision.requestId, userId: auth.userId, status: fresh?.status });\n      return reply('duplicate', `This request is already ${fresh?.status ?? 'decided'}.`, {\n        requestId: decision.requestId\n      });\n    }\n";
const CLICK_MOVED = "    const nowDate = now();\n    const claim = claimDecision({\n      requestId: decision.requestId,\n      action: decision.action,\n      userId: auth.userId,\n      username: auth.username,\n      requests: { [decision.requestId]: stored },\n      now: nowDate\n    });\n    if (claim.outcome === 'expired') {\n      await store.expire(stored, nowDate.toISOString());\n      return reply('expired', 'This approval request has expired.', { requestId: decision.requestId });\n    }\n    if (claim.outcome === 'duplicate') {\n      return reply('duplicate', `This request is already ${claim.status}.`, { requestId: decision.requestId });\n    }\n    if (claim.outcome !== 'claimed') {\n      return reply('rejected', 'Unknown or invalid approval request.', { requestId: decision.requestId });\n    }\n\n    try {\n      await store.claim(claim.request, nowDate.toISOString());\n    } catch (error) {\n      if (!(error instanceof ConditionFailed)) throw error;\n      // Someone else committed first (or it expired between read and write).\n      const fresh = await store.get(decision.requestId);\n      log({ event: 'claim_lost', requestId: decision.requestId, userId: auth.userId, status: fresh?.status });\n      return reply('duplicate', `This request is already ${fresh?.status ?? 'decided'}.`, {\n        requestId: decision.requestId\n      });\n    }\n\n    // Decided only for an authorized approver, and BEFORE any claim: a request\n    // whose commit is no longer allowed is not decided and changes no state.\n    if (framework.state !== 'allowed') {\n      log({\n        event: 'framework_revoked',\n        requestId: decision.requestId,\n        repositoryId,\n        userId: auth.userId,\n        state: framework.state,\n        reason: framework.reason,\n        frameworkSha: stored?.identity?.jobWorkflowSha ?? null\n      });\n      return reply('revoked', 'This request was filed by a framework commit that is no longer allowed. It cannot be decided.', {\n        requestId: decision.requestId\n      });\n    }\n";

// [invariant, file, search, replace]
export const MUTATIONS = [
  // --- the token is GitHub's, for this audience, and current ------------------
  ['signature verification cannot be bypassed', OIDC, "  if (!signed) reject('signature_invalid');\n", ''],
  ['the issuer is checked', OIDC, "  if (claims.iss !== GITHUB_OIDC_ISSUER) reject('issuer_mismatch');\n", ''],
  ['the audience is checked', OIDC, "  if (claims.aud !== BREAK_GLASS_AUDIENCE) reject('audience_mismatch');\n", ''],
  ['only RS256 is accepted', OIDC, "  if (header.alg !== 'RS256') reject('alg_not_allowed');", "  if (!['RS256', 'HS256', 'none'].includes(header.alg)) reject('alg_not_allowed');"],
  ['key-location header parameters are refused', OIDC, "  if (FORBIDDEN_HEADER_PARAMETERS.some((name) => Object.hasOwn(header, name))) reject('header_parameter_not_allowed');\n", ''],
  ['an expired token is refused', OIDC, "  if (exp <= nowSeconds) reject('token_expired');\n", ''],
  ['a token past its maximum age is refused', OIDC, "  if (nowSeconds - iat > maxAgeSeconds) reject('token_too_old');\n", ''],
  ['a not-yet-valid token is refused', OIDC, "    if (nbf > nowSeconds + skewSeconds) reject('token_not_yet_valid');\n", ''],
  ['a token issued in the future is refused', OIDC, "  if (iat > nowSeconds + skewSeconds) reject('token_issued_in_future');\n", ''],
  ['repository_id is required', OIDC, "    repositoryId: requireString(claims, 'repository_id', DECIMAL_ID),", '    repositoryId: claims.repository_id,'],
  // --- the token came from the framework's _break-glass-lambda.yml ------------
  ['job_workflow_ref repository is checked', OIDC, "  if (repository.toLowerCase() !== FRAMEWORK_REPOSITORY.toLowerCase()) reject('job_workflow_repository_not_allowed');\n", ''],
  ['the repository is compared case-insensitively', OIDC, '  if (repository.toLowerCase() !== FRAMEWORK_REPOSITORY.toLowerCase())', '  if (repository !== FRAMEWORK_REPOSITORY)'],
  ['job_workflow_ref path is checked', OIDC, "  if (!path) reject('job_workflow_path_not_allowed');\n", "  if (!path) return { repository, path: rest, ref: '' };\n"],
  ['the path is matched exactly', OIDC, '(allowed) => rest.startsWith(`${allowed}@`)', '(allowed) => rest.toLowerCase().startsWith(`${allowed.toLowerCase()}@`)'],
  ['_source-security.yml is not an accepted workflow', OIDC, "export const ALLOWED_JOB_WORKFLOW_PATHS = Object.freeze(['.github/workflows/_break-glass-lambda.yml']);", "export const ALLOWED_JOB_WORKFLOW_PATHS = Object.freeze(['.github/workflows/_break-glass-lambda.yml', '.github/workflows/_source-security.yml']);"],
  ['the ref part is bounded and printable', OIDC, "  if (!WORKFLOW_REF_NAME.test(ref)) reject('job_workflow_ref_malformed');\n", ''],
  ['job_workflow_sha must be 40 lower-case hex', OIDC, "sha: requireString(claims, 'job_workflow_sha', COMMIT_SHA) };", "sha: requireString(claims, 'job_workflow_sha') };"],
  // --- the framework commit policy (3D) ------------------------------------------
  ['notify checks the framework commit', BROKER, '    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);', "    const framework = action === 'notify' ? { state: 'allowed' } : await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);"],
  ['every status call checks the framework commit', BROKER, '    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);', "    const framework = action === 'status' ? { state: 'allowed' } : await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);"],
  ['the commit is checked BEFORE the token is spent', BROKER, AUTH_SPAN, AUTH_MOVED],
  ['a not-allowed commit is 403, not silently allowed', BROKER, "    if (framework.state !== 'allowed') {\n      log({ event: 'framework_rejected'", "    if (framework.state !== 'allowed' && framework.state !== 'not_allowed') {\n      log({ event: 'framework_rejected'"],
  ['only an exact allowed passes', POLICY, "  if (decision?.state === 'allowed') return result('allowed', null);", "  if (decision?.state === 'allowed' || decision?.state === 'absent') return result('allowed', null);"],
  ['an absent policy is never allowed', POLICY, "        if (error?.name === 'ParameterNotFound') return result('absent', 'no framework policy parameter');", "        if (error?.name === 'ParameterNotFound') return result('allowed', null);"],
  ['an unreadable policy is never allowed', POLICY, "        return result('unverified', `framework policy lookup failed (${error?.name || 'error'})`);", "        return result('allowed', null);"],
  ['a thrown check is never allowed', POLICY, "    return result('unverified', `framework policy check failed (${error?.name || 'error'})`);", "    return result('allowed', null);"],
  ['no configured policy allows nothing', POLICY, "  if (!frameworkPolicy || typeof frameworkPolicy.check !== 'function') return result('misconfigured', 'no framework policy configured');", "  if (!frameworkPolicy || typeof frameworkPolicy.check !== 'function') return result('allowed', null);"],
  ['the environment echo is validated', POLICY, "  if (parsed.environment !== environment) return result('malformed', `the value is for '${parsed.environment}', not '${environment}'`);\n", ''],
  ['commits must be strictly ascending', POLICY, "    if (!(shas[i - 1] < shas[i])) return result('malformed', 'commits are not strictly ascending (unsorted or duplicated)');\n", ''],
  ['duplicate commits are malformed', POLICY, '    if (!(shas[i - 1] < shas[i]))', '    if (!(shas[i - 1] <= shas[i]))'],
  ['entries must be lower-case 40-hex SHAs', POLICY, "  if (!shas.every((sha) => typeof sha === 'string' && COMMIT_SHA.test(sha))) {", "  if (!shas.every((sha) => typeof sha === 'string')) {"],
  ['the key set and order are exact', POLICY, '  if (keys.length !== KEYS.length || keys.some((key, i) => key !== KEYS[i])) {', '  if (!KEYS.every((key) => keys.includes(key))) {'],
  ['the policy set is bounded', POLICY, "  if (shas.length > MAX_ALLOWED_FRAMEWORK_SHAS) return result('malformed', `more than ${MAX_ALLOWED_FRAMEWORK_SHAS} commits`);\n", ''],
  ['the policy parameter must be a plain String', POLICY, "  if (!parameter || parameter.Type !== 'String') return result('malformed', 'parameter is not of type String');", "  if (!parameter) return result('malformed', 'parameter is not of type String');"],
  ['the policy environment is validated', POLICY, '  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) return null;\n  return `/ssd/break-glass/${environment}/governance/allowed-framework-shas`;', '  return `/ssd/break-glass/${environment}/governance/allowed-framework-shas`;'],
  ['the commit is validated before any lookup', POLICY, "      if (typeof sha !== 'string' || !COMMIT_SHA.test(sha)) return result('misconfigured', 'no valid framework commit to check');\n", ''],
  ['the click re-checks the stored commit', BROKER, '      decideFramework(frameworkPolicy, stored?.identity?.jobWorkflowSha)', "      Promise.resolve({ state: 'allowed' })"],
  ['a revoked commit is refused at click time', BROKER, "    if (framework.state !== 'allowed') {\n      log({\n        event: 'framework_revoked',", "    if (false) {\n      log({\n        event: 'framework_revoked',"],
  ['the click re-check comes BEFORE the claim', BROKER, CLICK_SPAN, CLICK_MOVED],
  ['the stored request records its commit', REQUEST, '      jobWorkflowSha: verified.jobWorkflow.sha,\n', ''],
  // --- CI secrets are read lazily (3D) -------------------------------------------
  ['the CI broker reads no secret before policy acceptance', RUNTIME, '    getBotToken = lazySecret(read(env.SLACK_BOT_TOKEN_SECRET_ARN));', '    const eager = await read(env.SLACK_BOT_TOKEN_SECRET_ARN)().catch(() => undefined);\n    getBotToken = async () => eager;'],
  ['the CI role selects lazy secrets', RUNTIME, "  if (role === 'ci') {", "  if (role === 'lazy') {"],
  ['a failed secret read is not cached', RUNTIME, '    })().finally(() => {\n      pending = undefined;\n    });', '    })();'],
  ['a secret with no value is a failure', RUNTIME, "      if (typeof secret !== 'string' || secret === '') throw new Error('secret has no value');\n", ''],
  ['the interaction function keeps reading secrets at start-up', RUNTIME, "  if (role === 'ci') {", "  if (role !== 'interactions-eager') {"],
  // --- JWKS is bounded and fails closed --------------------------------------
  ['an unknown kid cannot amplify JWKS fetches', OIDC, "        if (now() - lastAttemptAt < minRefreshIntervalMs) reject('unknown_kid');\n", ''],
  ['the JWKS cache expires', OIDC, '      if (!keys || now() - fetchedAt >= ttlMs) {', '      if (!keys) {'],
  ['undersized RSA keys are not trusted', OIDC, 'key.asymmetricKeyDetails.modulusLength < MIN_RSA_BITS', 'key.asymmetricKeyDetails.modulusLength < 512'],
  // --- the payload cannot be identity ------------------------------------------
  ['the repository is not derived from the payload', REQUEST, '    repository: verified.repository,\n    repositoryId: verified.repositoryId,\n    pullRequest,', '    repository: supplied.repository,\n    repositoryId: verified.repositoryId,\n    pullRequest,'],
  ['the PR number is not derived from the payload', REQUEST, '  const pullRequest = pullRequestFromIdentity(verified);', '  const pullRequest = String(payload.context.pullRequest);'],
  ['a production request needs a pull_request event', OIDC, "  if (identity?.eventName !== 'pull_request') reject('event_not_allowed');\n", ''],
  ['a payload that disagrees with the token is rejected', REQUEST, '    if (given !== undefined && given !== null && String(given) !== value) disagree(field);\n', ''],
  ['an unknown context field is rejected', REQUEST, "    if (!CONTEXT_FIELDS.has(field)) throw new IdentityRejected(`payload_context_field_not_allowed: ${field}`);\n", ''],
  ['approvers are looked up by the verified repository_id', BROKER, '    const repositoryId = stored?.identity?.repositoryId;', '    const repositoryId = stored?.context?.repositoryId;'],
  ['the audit comment refuses a request without verified identity', BROKER, "    if (!request?.identity) throw new Error('refusing side effects for a request without verified identity');\n", ''],
  ['an unconfigured verifier fails closed', BROKER, "      if (typeof verifyIdentity !== 'function') throw new IdentityRejected('verifier_not_configured');\n", "      if (typeof verifyIdentity !== 'function') return { identity: {} };\n"],
  // --- per-repository approvers in SSM (3B) -------------------------------------
  ['only a present list authorizes anyone', 'broker/authorize/slack-authorize.mjs', "  if (approvers?.state !== 'present' || !(approvers.userIds instanceof Set)) {", '  if (!(approvers?.userIds instanceof Set)) {'],
  ['an SSM failure is unverified, never absent', APPROVERS, "        if (error?.name === 'ParameterNotFound') return result('absent', 'no approver parameter');", "        return result('absent', 'no approver parameter');"],
  ['an empty list is reported as empty', APPROVERS, "  if (parsed.length === 0) return result('empty', 'the approver list is empty');\n", ''],
  ['one bad entry rejects the whole list', APPROVERS, "  if (!parsed.every((id) => typeof id === 'string' && SLACK_USER_ID.test(id))) {\n    return result('malformed', 'an entry is not a Slack user ID');\n  }\n  const userIds = new Set(parsed);", "  const userIds = new Set(parsed.filter((id) => typeof id === 'string' && SLACK_USER_ID.test(id)));"],
  ['entries must be Slack user IDs', APPROVERS, "typeof id === 'string' && SLACK_USER_ID.test(id))) {", "typeof id === 'string')) {"],
  ['duplicate approvers are malformed', APPROVERS, "  if (userIds.size !== parsed.length) return result('malformed', 'duplicate approver');\n", ''],
  ['the approver list is bounded', APPROVERS, "  if (parsed.length > MAX_APPROVERS) return result('malformed', `more than ${MAX_APPROVERS} approvers`);\n", ''],
  ['the parameter must be a plain String', APPROVERS, "  if (!parameter || parameter.Type !== 'String') return", '  if (!parameter) return'],
  ['the break-glass environment is validated', APPROVERS, '  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) return null;\n', ''],
  ['the repository_id in the parameter name is validated', APPROVERS, "  if (typeof repositoryId !== 'string' || !REPOSITORY_ID.test(repositoryId)) return null;\n", ''],
  // --- status is bound to the filing run --------------------------------------
  ['status is bound to repository_id', BROKER, '      owner.repositoryId !== auth.identity.repositoryId ||\n', ''],
  ['status is bound to run_id', BROKER, '      owner.runId !== auth.identity.runId ||\n', ''],
  ['status is bound to run_attempt', BROKER, '      owner.runId !== auth.identity.runId ||\n      owner.runAttempt !== auth.identity.runAttempt', '      owner.runId !== auth.identity.runId'],
  ['status requires a verified token', BROKER, "    const auth = await authenticate('status', identityToken, null);\n    if (auth.rejected) return auth.rejected;\n", "    const auth = { identity: {} };\n"],
  // --- a token is used once ---------------------------------------------------
  ['the replay record is a conditional write', STORE, "          ConditionExpression: 'attribute_not_exists(requestId)'\n        });\n        return true;", '        });\n        return true;'],
  ['a replayed token is refused', BROKER, '    if (!fresh) {', '    if (false) {'],
  ['a replay record is never read as a request', STORE, "  if (!item || typeof item.doc?.S !== 'string') return undefined;", '  if (!item) return undefined;'],
  // --- the client sends a fresh, masked token for this audience -----------------
  ['the client requests the ssd-break-glass audience', 'security/scripts/break-glass-oidc-token.mjs', "  url.searchParams.set('audience', BREAK_GLASS_AUDIENCE);", "  url.searchParams.set('audience', 'sts.amazonaws.com');"],
  ['the client masks the token', 'security/scripts/break-glass-oidc-token.mjs', '  mask(value);\n', ''],
  ['notify sends the identity token', 'security/scripts/break-glass-notify.mjs', "await invoke({ action: 'notify', payload, identityToken });", "await invoke({ action: 'notify', payload });"],
  ['every poll sends its own identity token', 'security/scripts/break-glass-poll.mjs', "await invoke({ action: 'status', requestId: request.requestId, identityToken });", "await invoke({ action: 'status', requestId: request.requestId });"],
  // --- the OIDC boundary --------------------------------------------------------
  ['_source-scan.yml stays OIDC-free', '.github/workflows/_source-scan.yml', '      pull-requests: write\n', '      pull-requests: write\n      id-token: write\n'],
  // --- Phase 3E: the end-to-end scenario table (test/break-glass-scenarios.test.js) ---
  ['3E: two concurrent claims cannot both win', STORE, "ConditionExpression: 'attribute_exists(#status) AND #status = :pending AND expiresAt > :now'", "ConditionExpression: 'attribute_exists(#status) AND expiresAt > :now'"],
  ['3E: a commit revoked while CI polls fails the poll', BROKER, "    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);\n    if (framework.state !== 'allowed') {", "    const framework = await decideFramework(frameworkPolicy, verified.jobWorkflow?.sha);\n    if (framework.state !== 'allowed' && action !== 'status') {"],
  ['3E: only an approval overrides the BLOCK', 'security/scripts/final-gate.mjs', "    [f.breakGlassDecision === 'approved',", "    [['approved', 'denied'].includes(f.breakGlassDecision),"],
  // --- Phase 3E: the live driver (tools/break-glass-live.mjs) is synthetic only ---
  ['3E live: only --environment synthetic is accepted', LIVE, "  if (values['--environment'] !== ENVIRONMENT) {", "  if (!['synthetic', 'production'].includes(values['--environment'])) {"],
  ['3E live: a secret-shaped flag is refused', LIVE, "    if (/secret|token|password/i.test(flag)) throw new LiveUsageError(`${flag}: the signing secret is read from stdin only, never from an argument`);\n", ''],
  ['3E live: a terminal stdin is refused', LIVE, "  if (stdin.isTTY) throw new LiveUsageError('pipe the signing secret on stdin (a terminal would echo it)');\n", ''],
  ['3E live: the caller account is checked', LIVE, '  for (const c of [accountCheck(caller, operator.aws.accountId), principalCheck(caller)]) {', '  for (const c of [principalCheck(caller)]) {'],
  ['3E live: the function must serve synthetic', LIVE, '  if (fn.value.variables.BREAK_GLASS_ENVIRONMENT !== ENVIRONMENT) {', '  if (false) {'],
  ['3E live: the Function URL must be the synthetic one', LIVE, '  if (normalizeFunctionUrl(url.value.url) !== functionUrl) {', '  if (false) {'],
  ['3E live: the target is proven before anything is sent', LIVE, '    const target = await resolveTarget({ operator, functionUrl: options.functionUrl, region: options.region, exec, env });\n', '    const target = { account: null, region: null, functionName: null, functionUrl: options.functionUrl };\n'],
  ['3E live: the secret never enters the evidence', LIVE, '    Object.assign(evidence, await runScenario(options, {', '    Object.assign(evidence, { signingSecret: secret }, await runScenario(options, {'],
  ['3E live: exactly one racing click may decide', LIVE, "    expect(JSON.stringify(outcomes) === JSON.stringify(['claimed', 'duplicate']),", "    expect(outcomes.includes('claimed'),"],
  ['3E live: the stale forgery is outside the five-minute window', LIVE, 'export const STALE_SECONDS = 600;', 'export const STALE_SECONDS = 60;'],
  ['3E live: a forgery must be refused 401', LIVE, "      expect(r.httpStatus === 401 && r.outcome === null,", "      expect(r.httpStatus !== 500,"],
  // --- Phase 3E: broker-side environment binding --------------------------------
  ['3E env: notify checks the request environment', BROKER, "    const misrouted = environmentRejection(payload.environment);\n    if (misrouted) return misrouted;\n", ''],
  ['3E env: the environment is checked before the token is spent', BROKER, "    const misrouted = environmentRejection(payload.environment);\n    if (misrouted) return misrouted;\n\n    const auth = await authenticate('notify', identityToken, payload.context.repository);\n    if (auth.rejected) return auth.rejected;\n", "    const auth = await authenticate('notify', identityToken, payload.context.repository);\n    if (auth.rejected) return auth.rejected;\n    const misrouted = environmentRejection(payload.environment);\n    if (misrouted) return misrouted;\n"],
  ['3E env: another environment is refused', BROKER, '    if (requested !== environment) {', '    if (false) {'],
  ['3E env: a malformed environment is refused as malformed', BROKER, '    if (!BREAK_GLASS_ENVIRONMENTS.includes(requested)) {', '    if (requested === undefined) {'],
  ['3E env: a broker without an environment refuses everything', BROKER, '    if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) {\n      log({ event: \'environment_rejected\', reason: \'broker_misconfigured\'', '    if (false) {\n      log({ event: \'environment_rejected\', reason: \'broker_misconfigured\''],
  ['3E env: the stored request records its environment', REQUEST, '    requestId: randomUUID(),\n    environment,\n', '    requestId: randomUUID(),\n'],
  ['3E env: status acts only on this environment\'s request', BROKER, '    if (!ownEnvironment(request)) {', '    if (false) {'],
  ['3E env: a click acts only on this environment\'s request', BROKER, '    if (stored && !ownEnvironment(stored)) {', '    if (false) {'],
  ['3E env: a request without an environment belongs nowhere', BROKER, '&& request?.environment === environment;', '&& (request?.environment ?? environment) === environment;'],
  ['3E env: the runtime binds the broker to BREAK_GLASS_ENVIRONMENT', RUNTIME, '    environment: env.BREAK_GLASS_ENVIRONMENT,\n', ''],
  ['3E env: Slack labels a synthetic request', 'broker/messages.mjs', "const prefix = (request) => (request.environment === 'synthetic' ? SYNTHETIC_PREFIX : '');", "const prefix = () => '';"],
  ['3E env: the client derives synthetic from a recorded fixture', NOTIFY, "  return active ? 'synthetic' : 'production';", "  return active ? 'production' : 'synthetic';"],
  ['3E env: the client refuses evidence without a synthetic record', NOTIFY, "  assert(typeof active === 'boolean', 'the gate evidence does not record whether it is synthetic; refusing to choose a broker environment');\n", ''],
  ['3E env: the client refuses a disagreeing preflight route', NOTIFY, "      assert(route === environment, `the preflight route '${route}' disagrees with the gate evidence ('${environment}'); refusing to send`);\n", ''],
  ['3E env: the Lambda payload carries the environment', NOTIFY, "    ...(environment ? { environment } : {}),\n", ''],
  ['3E env: the workflow passes the preflight route, never an input', '.github/workflows/_break-glass-lambda.yml', '          BREAK_GLASS_ROUTE: ${{ steps.preflight.outputs.route }}\n', '          BREAK_GLASS_ROUTE: ${{ inputs.toolkit_ref }}\n']
];

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMutationCheck({ tests: TESTS, mutations: MUTATIONS });
}
