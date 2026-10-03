// DynamoDB request store for the Lambda broker.
//
// Item layout (partition key `requestId`):
//   status       pending | processing | approved | denied | expired  (condition target)
//   expiresAt    ISO-8601 UTC, same format everywhere, so string order == time order
//   claimUserId  present only while a claim is in flight (finalize condition target)
//   slackChannel/slackTs  message reference, kept OUTSIDE `doc` so recording it can
//                never overwrite a concurrent claim
//   doc          the full request object as JSON (what the shared modules operate on)
//   ttl          epoch seconds for DynamoDB TTL cleanup (see RETENTION_SECONDS)
//
// The same table holds one-shot GitHub OIDC token records (see consumeTokenId),
// keyed `oidc-jti:<sha256(jti)>`. They carry no `doc` and no `status`, so they
// can never be read back as a request (fromItem) or satisfy any request
// transition's condition. Request ids are UUIDs, so the key spaces cannot meet.
//
// Every state transition is a conditional write. The pure decision modules decide
// WHAT the transition is; the condition makes it atomic, so two concurrent clicks
// can both read `pending` and still only one of them commits.
//
// `client.call(operation, input)` takes low-level DynamoDB API input; production
// binds it to the AWS SDK, tests bind it to an in-memory fake.

// DynamoDB TTL is physical cleanup only. Logical expiry is enforced in code at
// `expiresAt` (TTL deletion runs lazily, up to days late, so it can never be the
// expiry check). Decided items are kept for a week past expiry so a late CI poll
// still reads a terminal status rather than 404, and the decision stays inspectable.
export const RETENTION_SECONDS = 7 * 24 * 3600;

// A token record outlives its token: DynamoDB TTL never deletes BEFORE `ttl`,
// and the verifier refuses a token after `exp`, so a record is always present
// for as long as its token could verify. Deletion after `ttl` is lazy
// (typically within days) and harmless — the token is dead by then.
export const TOKEN_RECORD_GRACE_SECONDS = 3600;

export class ConditionFailed extends Error {}

const s = (value) => ({ S: String(value) });

function toItem(request) {
  return {
    requestId: s(request.requestId),
    status: s(request.status),
    expiresAt: s(request.expiresAt),
    ttl: { N: String(Math.floor(new Date(request.expiresAt).getTime() / 1000) + RETENTION_SECONDS) },
    doc: s(JSON.stringify(request))
  };
}

function fromItem(item) {
  if (!item || typeof item.doc?.S !== 'string') return undefined;
  const request = JSON.parse(item.doc.S);
  if (item.slackChannel && item.slackTs) {
    request.slack = { channel: item.slackChannel.S, ts: item.slackTs.S };
  }
  return request;
}

export function createDynamoStore({ client, tableName }) {
  const key = (requestId) => ({ requestId: s(requestId) });

  async function conditional(operation, input) {
    try {
      return await client.call(operation, { TableName: tableName, ...input });
    } catch (error) {
      if (error?.name === 'ConditionalCheckFailedException') throw new ConditionFailed(operation);
      throw error;
    }
  }

  return {
    // One-shot use of a verified GitHub OIDC token: an atomic conditional put
    // on the token's jti. Exactly one of any number of concurrent uses wins;
    // every other use — concurrent or later — returns false. Stores only what
    // an investigation needs: who (repository id, run), for what (action), and
    // when it may be cleaned up. Never the token.
    async consumeTokenId({ jtiHash, exp, repositoryId, runId, runAttempt, action }) {
      try {
        await conditional('PutItem', {
          Item: {
            requestId: s(`oidc-jti:${jtiHash}`),
            kind: s('oidc-jti'),
            action: s(action),
            repositoryId: s(repositoryId),
            runId: s(runId),
            runAttempt: s(runAttempt),
            tokenExp: { N: String(exp) },
            ttl: { N: String(exp + TOKEN_RECORD_GRACE_SECONDS) }
          },
          ConditionExpression: 'attribute_not_exists(requestId)'
        });
        return true;
      } catch (error) {
        if (error instanceof ConditionFailed) return false;
        throw error;
      }
    },

    async get(requestId) {
      const result = await client.call('GetItem', {
        TableName: tableName,
        Key: key(requestId),
        ConsistentRead: true
      });
      return fromItem(result.Item);
    },

    putPending: (request) =>
      conditional('PutItem', {
        Item: toItem(request),
        ConditionExpression: 'attribute_not_exists(requestId)'
      }),

    setSlackRef: (requestId, { channel, ts }) =>
      conditional('UpdateItem', {
        Key: key(requestId),
        UpdateExpression: 'SET slackChannel = :c, slackTs = :t',
        ConditionExpression: 'attribute_exists(requestId)',
        ExpressionAttributeValues: { ':c': s(channel), ':t': s(ts) }
      }),

    // Notify rollback when Slack refused the message: only a still-pending request.
    deletePending: (requestId) =>
      conditional('DeleteItem', {
        Key: key(requestId),
        ConditionExpression: '#status = :pending',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':pending': s('pending') }
      }),

    // pending -> processing. `request` is the object claimDecision already mutated.
    claim: (request, nowIso) =>
      conditional('UpdateItem', {
        Key: key(request.requestId),
        UpdateExpression: 'SET #status = :processing, claimUserId = :uid, doc = :doc',
        ConditionExpression: 'attribute_exists(#status) AND #status = :pending AND expiresAt > :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':processing': s('processing'),
          ':pending': s('pending'),
          ':uid': s(request.claim.userId),
          ':doc': s(JSON.stringify(request)),
          ':now': s(nowIso)
        }
      }),

    // processing -> approved|denied, only while OUR claim is the one in flight.
    // `request` is the object finalizeDecision already mutated; claimUserId is
    // passed separately because finalize removes the claim from the document.
    finalize: (request, claimUserId) =>
      conditional('UpdateItem', {
        Key: key(request.requestId),
        UpdateExpression: 'SET #status = :final, doc = :doc REMOVE claimUserId',
        ConditionExpression: '#status = :processing AND claimUserId = :uid',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':final': s(request.status),
          ':processing': s('processing'),
          ':uid': s(claimUserId),
          ':doc': s(JSON.stringify(request))
        }
      }),

    // pending -> expired, once expiresAt has passed. Losing the race is harmless.
    async expire(request, nowIso) {
      const expired = { ...request, status: 'expired' };
      delete expired.slack;
      try {
        await conditional('UpdateItem', {
          Key: key(request.requestId),
          UpdateExpression: 'SET #status = :expired, doc = :doc',
          ConditionExpression: '#status = :pending AND expiresAt <= :now',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':expired': s('expired'),
            ':pending': s('pending'),
            ':now': s(nowIso),
            ':doc': s(JSON.stringify(expired))
          }
        });
        return true;
      } catch (error) {
        if (error instanceof ConditionFailed) return false;
        throw error;
      }
    },

    // One-shot guard for the post-decision side effects, so a re-delivered async
    // event can never post a second audit comment.
    async claimSideEffects(requestId, nowIso) {
      try {
        await conditional('UpdateItem', {
          Key: key(requestId),
          UpdateExpression: 'SET sideEffectsAt = :now',
          ConditionExpression:
            'attribute_not_exists(sideEffectsAt) AND (#status = :approved OR #status = :denied)',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':now': s(nowIso),
            ':approved': s('approved'),
            ':denied': s('denied')
          }
        });
        return true;
      } catch (error) {
        if (error instanceof ConditionFailed) return false;
        throw error;
      }
    }
  };
}
