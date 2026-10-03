// Repository identity for `github plan` / `github apply`: PURE.
//
// The configured repository (.ssd/onboarding.yml repository.slug /
// defaultBranch) is the ONLY target. GitHub must report that exact repository
// (renames and transfers redirect, so full_name is compared, not just "the
// request worked") with that default branch, and the local origin must not
// name a different one:
//
//   known and mismatched         BLOCK, for plan and apply
//   origin unknown               WARN for plan; BLOCK for apply (a mutation is
//                                never made on an unresolved identity)
//   archived                     BLOCK
//
// Slugs compare case-insensitively (GitHub's own rule); branches exactly.
export const BLOCK = 'BLOCK';
export const WARN = 'WARN';
export const PASS = 'PASS';

const finding = (severity, kind, message) => ({ severity, kind, message });
const sameSlug = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// repository: discoverRepository() result. mode: 'plan' | 'apply'.
export function identityFindings({ config, facts, repository, mode }) {
  const { slug, defaultBranch } = config.repository;
  const findings = [];
  const git = facts?.git ?? {};
  if (git.slug && !sameSlug(git.slug, slug)) {
    findings.push(finding(BLOCK, 'origin-mismatch', `the local origin is ${git.slug}, but repository.slug is ${slug}`));
  } else if (!git.slug) {
    findings.push(
      finding(
        mode === 'apply' ? BLOCK : WARN,
        'origin-unknown',
        `the local origin is ${git.isGit ? 'absent or not a github.com remote' : 'unknown (not a git repository)'}, so the configured repository cannot be cross-checked locally${mode === 'apply' ? '; apply never mutates an unresolved identity' : ''}`
      )
    );
  }
  if (git.defaultBranch && git.defaultBranch !== defaultBranch) {
    findings.push(finding(BLOCK, 'origin-default-branch-mismatch', `the local origin/HEAD is ${git.defaultBranch}, but repository.defaultBranch is ${defaultBranch}`));
  }
  if (repository.state !== 'present') {
    findings.push(finding(BLOCK, 'repository-not-accessible', `GitHub did not return ${slug} to this token (${repository.reason}); its identity cannot be verified`));
    return findings;
  }
  const r = repository.value;
  if (!sameSlug(r.fullName, slug)) {
    findings.push(finding(BLOCK, 'identity-mismatch', `GitHub resolves ${slug} to ${r.fullName} (renamed or transferred?); correct repository.slug and re-plan`));
  }
  if (r.defaultBranch !== defaultBranch) {
    findings.push(finding(BLOCK, 'default-branch-mismatch', `GitHub reports the default branch ${r.defaultBranch}, but repository.defaultBranch is ${defaultBranch}`));
  }
  if (r.archived) {
    findings.push(finding(BLOCK, 'archived', `${r.fullName} is archived`));
  }
  if (!findings.some((f) => f.severity === BLOCK)) {
    findings.unshift(finding(PASS, 'identity', `GitHub repository ${r.fullName} (id ${r.id}), default branch ${r.defaultBranch}`));
  }
  return findings;
}

export const blocks = (findings) => findings.some((f) => f.severity === BLOCK);
