// Slack authorization: is the user who clicked an approver for THIS request's
// repository?
//
// The approver list comes from the per-repository SSM parameter named by the
// stored request's VERIFIED repository_id (broker/authorize/approvers.mjs) —
// never from the Slack interaction payload (Slack has no concept of a GitHub
// repository, so there is nothing there to trust) and never from a payload or
// display field. There is no environment-variable approver map any more, and
// no name-keyed lookup of any kind.
//
// `approvers` is an approvers.mjs lookup result. Only `present` authorizes
// anyone; every other state — absent, empty, malformed, unverified,
// misconfigured — authorizes nobody.

// Reached only AFTER signature verification.
export function authorizeSlackInteraction({ interaction, approvers }) {
  const user = interaction?.user;
  const userId = user?.id;
  const username = user?.username || user?.name || userId;
  if (!userId) return { authorized: false, reason: 'missing Slack user identity' };
  if (approvers?.state !== 'present' || !(approvers.userIds instanceof Set)) {
    return { authorized: false, userId, username, reason: `approver list ${approvers?.state ?? 'unavailable'}` };
  }
  if (!approvers.userIds.has(String(userId))) {
    return { authorized: false, userId, username, reason: 'not an authorized break-glass approver' };
  }
  return { authorized: true, userId, username };
}
