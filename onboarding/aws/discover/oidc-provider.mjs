// The account's GitHub Actions OIDC identity provider (shared scope).
// Discovery only: thumbprints and audiences are reported, never changed.
import { GITHUB_OIDC_HOST } from '../policy/trust.mjs';
import { absent, present, read } from './result.mjs';

const PROVIDER_ARN = /^arn:[^:]+:iam::(\d{12}):oidc-provider\/(.+)$/;

// -> result whose value is { arn, account, url, clientIds[], thumbprints[], tags[], others[] }
export async function discoverOidcProvider(aws, { account }) {
  const listed = await read(aws, ['iam', 'list-open-id-connect-providers']);
  if (listed.state !== 'present') {
    return listed;
  }
  const arns = (Array.isArray(listed.value.OpenIDConnectProviderList) ? listed.value.OpenIDConnectProviderList : [])
    .map((entry) => (typeof entry?.Arn === 'string' ? entry.Arn : null))
    .filter(Boolean);
  const github = arns.filter((arn) => PROVIDER_ARN.exec(arn)?.[2] === GITHUB_OIDC_HOST);
  if (github.length === 0) {
    return absent('NotListed');
  }
  // Prefer the provider in the expected account; report any other.
  const chosen = github.find((arn) => PROVIDER_ARN.exec(arn)[1] === account) ?? github[0];
  const others = github.filter((arn) => arn !== chosen);
  const got = await read(aws, ['iam', 'get-open-id-connect-provider', '--open-id-connect-provider-arn', chosen], { notFound: ['NoSuchEntity'] });
  if (got.state !== 'present') {
    return got;
  }
  const v = got.value;
  return present({
    arn: chosen,
    account: PROVIDER_ARN.exec(chosen)[1],
    url: typeof v.Url === 'string' ? v.Url.replace(/^https:\/\//, '') : null,
    clientIds: Array.isArray(v.ClientIDList) ? v.ClientIDList.map(String) : [],
    thumbprints: Array.isArray(v.ThumbprintList) ? v.ThumbprintList.map(String) : [],
    tags: tagList(v.Tags),
    others
  });
}

export const tagList = (tags) => (Array.isArray(tags) ? tags.filter((t) => t && typeof t.Key === 'string').map((t) => ({ key: t.Key, value: String(t.Value ?? '') })) : []);
