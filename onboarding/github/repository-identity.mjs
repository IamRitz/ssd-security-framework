// The GitHub facts a Phase 3D break-glass repository stack is keyed on
// (docs/break-glass-repositories.md § Repository configuration):
//
//   repository  GET repos/<slug>  -> { id, fullName }
//               the immutable repository_id the approver parameter and the
//               invoker role are named after, and GitHub's exact spelling of
//               owner/name (the default OIDC subject uses it);
//   oidc        GET repos/<slug>/actions/oidc/customization/sub
//               -> { useDefault, includeClaimKeys }
//               whether GitHub issues the DEFAULT subject repo:<o>/<r>:<context>.
//
// Read-only (identityGh: two GETs of one repository). Every failure is
// reported, never guessed: a 404 is `absent` (GitHub also answers 404 for "no
// access"), anything else `unverified`. The caller decides; the break-glass
// plan blocks on anything short of `present`.
import { GhCliError, identityGh } from './gh-cli.mjs';

const present = (value) => ({ state: 'present', value });
const failed = (error) =>
  error instanceof GhCliError && error.kind === 'not-found'
    ? { state: 'absent', error: { kind: error.kind, status: error.status, message: error.message } }
    : { state: 'unverified', error: { kind: error?.kind ?? 'runtime', status: error?.status ?? null, message: error?.message ?? String(error) } };

export async function discoverRepositoryIdentity({ slug, exec, env = process.env, timeoutMs, deadlineMs, now }) {
  let gh;
  try {
    gh = identityGh({ slug, exec, env, timeoutMs, deadlineMs, now });
  } catch (error) {
    return { repository: failed(error), oidc: failed(error) };
  }
  const read = async (name, shape) => {
    try {
      return shape(await gh.get(name));
    } catch (error) {
      return failed(error);
    }
  };
  const repository = await read('repository', (r) =>
    Number.isSafeInteger(r?.id) && r.id > 0 && typeof r.full_name === 'string'
      ? present({ id: String(r.id), fullName: r.full_name })
      : { state: 'unverified', error: { kind: 'malformed-response', status: null, message: 'the repository has no numeric id or full_name' } }
  );
  const oidc = await read('oidcSubject', (r) =>
    typeof r?.use_default === 'boolean'
      ? present({ useDefault: r.use_default, includeClaimKeys: Array.isArray(r.include_claim_keys) ? r.include_claim_keys.map(String) : [] })
      : { state: 'unverified', error: { kind: 'malformed-response', status: null, message: 'the OIDC subject customization has no boolean use_default' } }
  );
  return { repository, oidc };
}
