// Per-repository break-glass approvers, read from SSM Parameter Store
// (architecture E.3).
//
//   /ssd/break-glass/<environment>/approvers/<repository_id>
//   Type String, value: a JSON array of Slack user IDs, e.g. ["U0BV6TWN60J"]
//
// One parameter per repository, so onboarding a repository never touches the
// shared interaction function's configuration. The repository_id is ALWAYS the
// stored request's verified identity (broker/identity/github-oidc.mjs), never a
// payload or display value; this module only ever asks for the one parameter
// that identity names, so another repository's list is never consulted.
//
// Fail closed, with the reason kept distinct for operators:
//   present        a valid, non-empty list            -> only those users
//   absent         no such parameter                   -> nobody
//   empty          []                                  -> nobody
//   malformed      bad JSON / type / entry / size      -> nobody (never filtered)
//   unverified     SSM refused, failed or timed out    -> nobody (NOT "absent")
//   misconfigured  bad environment or repository_id    -> nobody, no SSM call
//
// No cache: the lookup happens at click time, so removing an approver from the
// parameter takes effect on the next click.

export const APPROVER_PARAMETER_ROOT = '/ssd/break-glass';
export const BREAK_GLASS_ENVIRONMENTS = Object.freeze(['production', 'synthetic']);
export const MAX_APPROVERS = 50;
const MAX_VALUE_LENGTH = 4096;
const REPOSITORY_ID = /^[1-9][0-9]{0,19}$/;
// Slack user IDs: U… (workspace) or W… (Enterprise Grid), uppercase alphanumerics.
export const SLACK_USER_ID = /^[UW][A-Z0-9]{8,20}$/;

// -> the exact parameter name, or null when either component is invalid.
export function approverParameterName(environment, repositoryId) {
  if (!BREAK_GLASS_ENVIRONMENTS.includes(environment)) return null;
  if (typeof repositoryId !== 'string' || !REPOSITORY_ID.test(repositoryId)) return null;
  return `${APPROVER_PARAMETER_ROOT}/${environment}/approvers/${repositoryId}`;
}

const result = (state, reason, userIds = null) => ({ state, reason, userIds });

// A parameter value -> present | empty | malformed. One bad entry rejects the
// whole list: a list that does not parse exactly as written is not the list
// its owner reviewed.
export function parseApproverList(value) {
  if (typeof value !== 'string' || value.length > MAX_VALUE_LENGTH) return result('malformed', 'value is not a bounded string');
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return result('malformed', 'value is not JSON');
  }
  if (!Array.isArray(parsed)) return result('malformed', 'value is not a JSON array');
  if (parsed.length === 0) return result('empty', 'the approver list is empty');
  if (parsed.length > MAX_APPROVERS) return result('malformed', `more than ${MAX_APPROVERS} approvers`);
  if (!parsed.every((id) => typeof id === 'string' && SLACK_USER_ID.test(id))) {
    return result('malformed', 'an entry is not a Slack user ID');
  }
  const userIds = new Set(parsed);
  if (userIds.size !== parsed.length) return result('malformed', 'duplicate approver');
  return result('present', null, userIds);
}

// getParameter(name) -> { Type, Value } (the SSM GetParameter `Parameter`), or
// throws; an error named ParameterNotFound means the parameter does not exist.
export function createApproverSource({ getParameter, environment }) {
  return {
    async approversFor(repositoryId) {
      const name = approverParameterName(environment, repositoryId);
      if (!name) return result('misconfigured', 'invalid break-glass environment or repository_id');
      let parameter;
      try {
        parameter = await getParameter(name);
      } catch (error) {
        if (error?.name === 'ParameterNotFound') return result('absent', 'no approver parameter');
        // Access denied, throttling, timeout, network: the list is UNKNOWN.
        return result('unverified', `approver lookup failed (${error?.name || 'error'})`);
      }
      if (!parameter || parameter.Type !== 'String') return result('malformed', 'parameter is not of type String');
      return parseApproverList(parameter.Value);
    }
  };
}
