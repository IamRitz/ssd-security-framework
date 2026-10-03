// Test-only preload (`node --import`) standing in for the GitHub Actions runner's
// OIDC token endpoint, so tests can spawn the REAL CI scripts end to end.
//
// Active only when SSD_TEST_OIDC_TOKEN is set. It answers requests to
// ACTIONS_ID_TOKEN_REQUEST_URL only when they carry the runner's request token
// (SSD_TEST_OIDC_REQUEST_TOKEN — what the runner would accept, independent of
// what the script under test sends) and ask for the `ssd-break-glass`
// audience — so a script that requested the
// wrong audience, or forgot the request token, fails here as it would on GitHub.
const token = process.env.SSD_TEST_OIDC_TOKEN;
const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;

if (token && requestUrl) {
  const realFetch = globalThis.fetch;
  const endpoint = new URL(requestUrl);
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    if (url.origin !== endpoint.origin || url.pathname !== endpoint.pathname) return realFetch(input, init);
    const authorization = new Headers(init.headers).get('authorization');
    if (authorization !== `bearer ${process.env.SSD_TEST_OIDC_REQUEST_TOKEN}`) {
      return new Response('', { status: 401 });
    }
    if (url.searchParams.get('audience') !== 'ssd-break-glass') return new Response('', { status: 400 });
    return new Response(JSON.stringify({ value: token }), { status: 200 });
  };
}
