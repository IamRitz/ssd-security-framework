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
  if (!item) return undefined;
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
