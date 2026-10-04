// Break-glass is only offered for these BLOCK categories — the same allowlist the
// n8n notify node enforced. Never secrets, never malicious packages, never a
// report-integrity failure.
//
// (The Express service's loadConfig, with its name-keyed approver map, was not
// carried over: the Lambda broker reads approvers from SSM by repository_id.)
export const ELIGIBLE_POLICY_RULES = new Set([
  'sast.critical_new',
  'sast.high_new',
  'dependencies.critical_with_fix',
  'dependencies.high_with_fix'
]);
