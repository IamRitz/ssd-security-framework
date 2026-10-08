# Break-glass broker (AWS Lambda)

The server side of Lambda break-glass: the CI broker that records an approval
request and the Slack interaction handler that decides it. The CI side (the
scripts `_break-glass-lambda.yml` runs) lives in `security/scripts/`.

## Provenance

Imported from `IamRitz/secure-software-delivery` at commit
`6c37d7ddb4376052c0ce0876922bf9b501462b4e`, behaviour unchanged. Only import
specifiers were rewritten for the new layout:

| Here | Source |
| --- | --- |
| `broker/{request,config,messages,slack,github}.mjs` | `server/break-glass/` |
| `broker/lambda/*.mjs` | `server/break-glass/lambda/` |
| `broker/authorize/{slack-interaction-verify,slack-authorize,break-glass-decision}.mjs` | `security/scripts/` |
| `test/broker-lambda.test.js` | `test/break-glass-lambda.test.js` |
| `test/broker-authorize.test.js` | `test/slack-break-glass.test.js` |
| `test/support/fake-dynamodb.mjs` | `test/helpers/fake-dynamodb.mjs` |

Deliberately **not** imported:

- the Express HTTP transport (`app.mjs`, `server.mjs`, `store.mjs`) and the n8n
  workflows: the HTTP transport is never generated (architecture E.1);
- `infra/deploy.sh`: imperative provisioning that adopts resources by name.
  Shared break-glass infrastructure is provisioned by reviewed CloudFormation
  in Phase 3C (architecture E.4);
- `infra/verify-live.mjs`: ported in Phase 3E, against the synthetic stack only.

## Architecture

| Path | Function | Invocation | Authentication | Public |
| --- | --- | --- | --- | --- |
| notify (CI → broker) | CI broker | `lambda:InvokeFunction` | GitHub OIDC → per-repository invoker role | No |
| status (CI poll) | CI broker | `lambda:InvokeFunction` | same | No |
| Slack interaction | interactions | Function URL | Slack HMAC signature | **Yes — the only public surface** |

Both functions ship the same bundle and differ by handler
(`broker/lambda/index.ciHandler`, `broker/lambda/index.interactionsHandler`).

- **State.** One DynamoDB table keyed by `requestId`. Every transition is a
  conditional write, so concurrent clicks are safe by construction. TTL on
  `ttl` is physical cleanup only (7 days after `expiresAt`); logical expiry is
  checked in code.
- **Slack's 3-second ack.** Verify, authorize, claim and finalize run before the
  response; the Slack message update and the PR audit comment follow in an async
  self-invocation guarded by a one-shot `sideEffectsAt` conditional write.
- **Secrets.** Slack bot token, Slack signing secret and the GitHub credential
  that posts the audit comment, each readable only by the execution role that
  needs it. GitHub Actions holds no secret for this path. The CI function
  reads its secrets lazily, only when it posts (`lazySecret` in
  `lambda/runtime.mjs`); the interaction function reads them at start-up.
- **Framework commit (Phase 3D).** Only `_break-glass-lambda.yml` may file,
  and its verified `job_workflow_sha` must be in
  `/ssd/break-glass/<BREAK_GLASS_ENVIRONMENT>/governance/allowed-framework-shas`,
  checked on notify, every status call and every click
  (`identity/framework-policy.mjs`;
  [docs/break-glass-repositories.md](../docs/break-glass-repositories.md)).
- **Dependencies.** Node builtins only, plus the AWS SDK v3 clients the Lambda
  Node.js runtime provides (loaded lazily in `lambda/runtime.mjs`); nothing is
  bundled.
