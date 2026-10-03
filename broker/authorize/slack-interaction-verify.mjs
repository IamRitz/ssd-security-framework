import { createHmac, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { URLSearchParams } from 'node:url';

// Slack signs `v0:{timestamp}:{raw_body}` with the app's Signing Secret using
// HMAC-SHA256 (Node built-in, no external package — same discipline as the
// Discord Ed25519 module). The signature MUST be checked against the raw,
// un-parsed request body; parsing/re-serializing changes the bytes and silently
// breaks verification against genuine Slack requests.
export function verifySlackSignature({
  signingSecret,
  signature,
  timestamp,
  rawBody,
  now = Date.now(),
  toleranceSeconds = 300
}) {
  try {
    if (typeof signingSecret !== 'string' || signingSecret === '') return false;
    if (typeof signature !== 'string' || !/^v0=[0-9a-f]{64}$/i.test(signature)) return false;
    // Reject anything non-numeric or outside the 5-minute window so a genuinely
    // signed but replayed request cannot be accepted (Slack's replay guidance).
    if (typeof timestamp !== 'string' || !/^\d+$/.test(timestamp)) return false;
    const sentSeconds = Number(timestamp);
    const nowSeconds = Math.floor((now instanceof Date ? now.getTime() : now) / 1000);
    if (!Number.isFinite(sentSeconds) || Math.abs(nowSeconds - sentSeconds) > toleranceSeconds) {
      return false;
    }

    const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody ?? '', 'utf8');
    const base = Buffer.concat([Buffer.from(`v0:${timestamp}:`, 'utf8'), body]);
    const expected = `v0=${createHmac('sha256', signingSecret).update(base).digest('hex')}`;

    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(signature, 'utf8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// Only call AFTER verifySlackSignature passes. Slack interactive callbacks are
// application/x-www-form-urlencoded with a `payload` field holding URL-encoded
// JSON — not raw JSON like Discord.
export function parseSlackInteraction(rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody ?? '');
  const payload = new URLSearchParams(body).get('payload');
  if (!payload) throw new Error('missing Slack payload field');
  return JSON.parse(payload);
}

// Extract the break-glass request id and action from the clicked block button.
// Buttons carry `action_id` (or `value`) of the form breakglass:{uuid}:{approve|deny},
// mirroring Discord's custom_id scheme.
export function extractSlackDecision(interaction) {
  const control = interaction?.actions?.[0];
  const identifier = control?.action_id || control?.value || '';
  const match = /^breakglass:([0-9a-f-]{36}):(approve|deny)$/.exec(identifier);
  if (!match) return null;
  return { requestId: match[1], action: match[2] };
}
