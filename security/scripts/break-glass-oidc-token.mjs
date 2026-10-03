// Mints the GitHub OIDC token that proves to the break-glass broker WHICH
// repository, pull request and run is asking (audience `ssd-break-glass`, a
// different audience from the `sts.amazonaws.com` token the job uses to assume
// its AWS role). Notify and every status poll mint their own: tokens live 300 s,
// and the broker accepts each token once.
//
// Only a job granted `id-token: write` has ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN.
// The framework jobs that call this already hold that grant
// (_break-glass-lambda.yml's job, legacy _source-security.yml's source-gate);
// _source-scan.yml never invokes the Lambda broker and never calls this.
//
// The token is masked the moment it exists (the same `add-mask` workflow
// command @actions/core's getIDToken issues; the runner consumes it and prints
// nothing), it never enters argv, a file this module writes, an output or a
// summary, and no error message here contains any part of it — or the runner's
// request token.
import { URL } from 'node:url';

export const BREAK_GLASS_AUDIENCE = 'ssd-break-glass';
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export async function mintBreakGlassIdentityToken({
  env = process.env,
  fetchImpl = globalThis.fetch,
  mask = (value) => process.stdout.write(`::add-mask::${value}\n`)
} = {}) {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new Error('GitHub OIDC is not available to this job (it needs `id-token: write`); no identity token for the break-glass broker');
  }
  let url;
  try {
    url = new URL(requestUrl);
  } catch {
    throw new Error('ACTIONS_ID_TOKEN_REQUEST_URL is not a valid URL');
  }
  if (url.protocol !== 'https:') throw new Error('ACTIONS_ID_TOKEN_REQUEST_URL must use HTTPS');
  url.searchParams.set('audience', BREAK_GLASS_AUDIENCE);

  let response;
  try {
    response = await fetchImpl(url, {
      headers: { authorization: `bearer ${requestToken}`, accept: 'application/json' },
      signal: globalThis.AbortSignal.timeout(15_000)
    });
  } catch (error) {
    throw new Error(`GitHub OIDC token request failed (${error?.name || 'error'})`);
  }
  if (!response.ok) throw new Error(`GitHub OIDC token request returned HTTP ${response.status}`);
  let value;
  try {
    ({ value } = await response.json());
  } catch {
    throw new Error('GitHub OIDC token response is not JSON');
  }
  if (typeof value !== 'string' || !JWT_SHAPE.test(value)) {
    throw new Error('GitHub OIDC token response carries no token');
  }
  mask(value);
  return value;
}
