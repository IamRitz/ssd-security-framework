// The shared GitHub OIDC provider stack (ssd-shared-github-oidc): the
// account's IAM OIDC identity provider for token.actions.githubusercontent.com
// with the single audience sts.amazonaws.com. Planned only when
// delivery.oidcProvider is `managed`.
//
// No thumbprint is listed: AWS::IAM::OIDCProvider does not require
// ThumbprintList (CloudFormation resource schema). Hard-coding a certificate
// thumbprint would pin a value that rotates; whether IAM accepts the provider
// without one is observed when the change set is executed (Phase 2C), not
// asserted here.
import { GITHUB_OIDC_HOST, STS_AUDIENCE } from '../policy/trust.mjs';
import { retained, ssdTags, template } from './common.mjs';

export const OIDC_LOGICAL_ID = 'GitHubOidcProvider';

export function renderOidcTemplate() {
  return {
    template: template('ssd-onboard shared GitHub Actions OIDC identity provider', {
      [OIDC_LOGICAL_ID]: retained('AWS::IAM::OIDCProvider', {
        Url: `https://${GITHUB_OIDC_HOST}`,
        ClientIdList: [STS_AUDIENCE],
        Tags: ssdTags({ scope: 'shared' })
      })
    }),
    policies: {}
  };
}
