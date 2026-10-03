// Lambda entry-point logic, separated from AWS SDK wiring (runtime.mjs) so tests
// drive it with fakes.
//
// Two functions, two auth models:
//   break-glass-ci           direct lambda:InvokeFunction only (GitHub OIDC -> IAM).
//                            No Function URL, no resource policy: unreachable from
//                            the internet.
//   break-glass-interactions Function URL (auth NONE) for Slack, authenticated by
//                            the Slack HMAC signature. Also receives its own async
//                            follow-up events, which a URL request cannot forge:
//                            URL events always carry requestContext.http.
import { Buffer } from 'node:buffer';

const isUrlEvent = (event) => Boolean(event?.requestContext?.http);

export function createCiHandler({ getBroker }) {
  return async function ciHandler(event) {
    // Defense in depth: this function must never be wired to a URL or API gateway.
    if (isUrlEvent(event) || event?.headers) return { ok: false, statusCode: 403, error: 'direct_invoke_only' };
    const broker = await getBroker();
    if (event?.action === 'notify') return broker.notify(event.payload);
    if (event?.action === 'status') return broker.status(event.requestId);
    return { ok: false, statusCode: 400, error: 'unknown_action' };
  };
}

export function createInteractionsHandler({ getBroker, enqueue }) {
  return async function interactionsHandler(event) {
    if (!isUrlEvent(event)) {
      // Async follow-up event this function sent itself.
      const broker = await getBroker();
      return broker.runFollowUp(event);
    }
    if (event.requestContext.http.method !== 'POST') return respond(405, 'method_not_allowed');

    const headers = Object.fromEntries(
      Object.entries(event.headers || {}).map(([name, value]) => [name.toLowerCase(), String(value)])
    );
    const rawBody = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');

    const broker = await getBroker();
    const result = await broker.handleInteraction({ headers, rawBody });
    if (result.followUp) {
      try {
        await enqueue(result.followUp);
      } catch (error) {
        // The decision is already finalized; do the side effects inline rather
        // than drop the audit comment. Slack may show a slow ack, never a lost one.
        console.error(`follow-up enqueue failed, running inline: ${error.message}`);
        await broker.runFollowUp(result.followUp).catch((inner) => {
          console.error(`inline follow-up failed: ${inner.message}`);
        });
      }
    }
    const body =
      result.statusCode === 401 ? 'invalid_request_signature' : result.statusCode === 400 ? 'invalid_payload' : '';
    return respond(result.statusCode, body, result.outcome);
  };
}

function respond(statusCode, error, outcome) {
  const headers = { 'content-type': 'application/json' };
  // Reported only for signed, parsed requests — lets the live race test count
  // outcomes without reading logs. Unsigned callers learn nothing beyond 401.
  if (outcome && statusCode === 200) headers['x-break-glass-outcome'] = outcome;
  return { statusCode, headers, body: error ? JSON.stringify({ error }) : '' };
}
