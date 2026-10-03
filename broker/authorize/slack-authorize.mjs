// Slack authorization: a PER-REPO approver allowlist.
//
// Pure logic with no dependency on n8n or any host. It's wired into the n8n
// workflow today because that's the platform in use, but nothing here knows about
// n8n — a future plain Node/Slack-Bolt service imports it unchanged; only the
// config source (env var) and the pending-request store would be re-wired.
//
// The repo identity is supplied by the caller from STORED request state (set at
// notify time from the CI payload), never from the Slack interaction payload —
// Slack has no concept of a GitHub repo, so there is nothing there to trust.

// Parse SLACK_APPROVER_IDS_BY_REPO — a JSON object of "owner/repo" -> ["Uxxx", ...]
// — into a Map<string, Set<string>>. Fail closed: any parse or shape failure
// returns an EMPTY map (nobody authorized for anything), logged, never thrown, so
// one bad config edit cannot crash the interaction handler for every repo at once.
export function parseApproverMapFromEnv(envValue) {
  const map = new Map();
  if (typeof envValue !== 'string' || envValue.trim() === '') return map;

  let parsed;
  try {
    parsed = JSON.parse(envValue);
  } catch (error) {
    console.error(
      `SLACK_APPROVER_IDS_BY_REPO is not valid JSON; treating as empty (nobody authorized): ${error.message}`
    );
    return map;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    console.error('SLACK_APPROVER_IDS_BY_REPO must be a JSON object of repo -> [userId]; treating as empty');
    return map;
  }

  for (const [repo, ids] of Object.entries(parsed)) {
    if (!Array.isArray(ids)) continue;
    map.set(repo, new Set(ids.map((id) => String(id).trim()).filter(Boolean)));
  }
  return map;
}

// Authorized only if `repo` is an explicit key in the map AND `userId` is in that
// repo's set. A repo with no entry authorizes NOBODY — fail closed, not a fallback
// to some default list. That matches the onboarding rule: no entry = not onboarded.
export function isAuthorizedApprover(userId, repo, approverMap) {
  if (!userId || !repo || !(approverMap instanceof Map)) return false;
  const allowed = approverMap.get(repo);
  return Boolean(allowed && allowed.has(String(userId)));
}

// Reached only AFTER signature verification. `repo` is the stored request's repo.
export function authorizeSlackInteraction({ interaction, repo, approverMap }) {
  const user = interaction?.user;
  const userId = user?.id;
  const username = user?.username || user?.name || userId;
  if (!userId) return { authorized: false, reason: 'missing Slack user identity' };
  if (!isAuthorizedApprover(userId, repo, approverMap)) {
    return { authorized: false, userId, username, repo, reason: 'not an authorized break-glass approver' };
  }
  return { authorized: true, userId, username, repo };
}
