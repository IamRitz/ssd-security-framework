// The CloudFormation stack names ssd-onboard owns. This is a CONTRACT: doctor
// locates ownership only in exactly these stacks, and Phase 2B must create
// stacks under exactly these names. Names are derived, never configured.
//
// A name is a LOCATOR, not proof: ownership additionally requires the stack's
// tags and state (discover/stacks.mjs).
//
//   canonical repository   github.com/<owner>/<repo>, lower-cased (GitHub owner
//                          and repository names are case-insensitive, so
//                          Acme/My-App and acme/my-app are ONE repository)
//   per repository         ssd-delivery-<display>-<h8>
//                          <display>: owner-repo, every run of characters
//                          outside [a-z0-9] -> '-' (for humans only)
//                          <h8>: first 8 hex digits of sha256(canonical), so
//                          repositories whose display names coincide
//                          (acme/my.app vs acme/my-app, a-b/c vs a/b-c) still
//                          get different names. At most 128 characters.
//   shared                 ssd-shared-github-oidc    (the account's GitHub OIDC provider)
//                          ssd-shared-ecr-scanning   (registry scanning configuration)
//
// Every name is looked up in delivery.aws.region: a stack of the same name in
// another region is not the expected stack.
import { createHash } from 'node:crypto';

export const SHARED_STACKS = Object.freeze({
  githubOidc: 'ssd-shared-github-oidc',
  ecrScanning: 'ssd-shared-ecr-scanning'
});

// The class every Phase 2 delivery stack carries (`synthetic` belongs to the
// Phase 3 break-glass test stack, architecture E.4).
export const DELIVERY_ENVIRONMENT = 'production';

// Phase 3C: the two shared break-glass stacks, one per environment. Each holds
// its own functions, table, secrets and execution roles; nothing is shared
// between them but the (immutable) code artifact. The environment is part of
// the name AND the ssd:environment tag, and ownership requires both to agree.
export const BREAK_GLASS_ENVIRONMENTS = Object.freeze(['production', 'synthetic']);
export const BREAK_GLASS_STACKS = Object.freeze({
  production: 'ssd-break-glass-production',
  synthetic: 'ssd-break-glass-synthetic'
});
// The plan stack kind of each environment's stack (plan/scope.mjs).
export const breakGlassStackKind = (environment) => `break-glass-${environment}`;
// stack kind -> environment, or null for a kind that is not a break-glass stack.
export function breakGlassEnvironmentOf(stackKind) {
  const environment = typeof stackKind === 'string' && stackKind.startsWith('break-glass-') ? stackKind.slice('break-glass-'.length) : null;
  return BREAK_GLASS_ENVIRONMENTS.includes(environment) ? environment : null;
}

const PREFIX = 'ssd-delivery-';
const MAX_STACK_NAME = 128;
export const STACK_NAME = /^[A-Za-z][A-Za-z0-9-]{0,127}$/;

function parts(slug) {
  if (typeof slug !== 'string' || !/^[^/\s]+\/[^/\s]+$/.test(slug)) {
    throw new Error(`cannot derive a repository identity from slug '${slug}'`);
  }
  return slug.toLowerCase().split('/');
}

// The value of the ssd:consumer-repository tag: owner/repo, lower-cased.
export const canonicalSlug = (slug) => parts(slug).join('/');

// The identity the stack-name hash is computed over.
export const canonicalRepository = (slug) => `github.com/${canonicalSlug(slug)}`;

const display = (text) => text.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

export function repoStackName(slug) {
  const [owner, repo] = parts(slug);
  const digest = createHash('sha256').update(canonicalRepository(slug)).digest('hex').slice(0, 8);
  const room = MAX_STACK_NAME - PREFIX.length - 1 - digest.length;
  const body = [display(owner), display(repo)].filter(Boolean).join('-').slice(0, room).replace(/-+$/, '');
  return `${PREFIX}${body ? `${body}-` : ''}${digest}`;
}
