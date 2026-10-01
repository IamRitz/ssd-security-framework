// The configured ECR repository (per-repository scope) and the registry
// scanning configuration (shared scope). Facts are reported as observed;
// framework invariants are judged by the doctor, not here.
import { tagList } from './oidc-provider.mjs';
import { absent, present, read } from './result.mjs';

// -> result whose value is { arn, uri, registryId, tagMutability, tagMutabilityExclusions[],
//    scanOnPush, encryption, lifecyclePolicy, repositoryPolicy, tags }
// where lifecyclePolicy / repositoryPolicy / tags are themselves results.
export async function discoverRepository(aws, { account, repository }) {
  const described = await read(aws, ['ecr', 'describe-repositories', '--registry-id', account, '--repository-names', repository], {
    notFound: ['RepositoryNotFoundException']
  });
  if (described.state !== 'present') {
    return described;
  }
  const repo = (Array.isArray(described.value.repositories) ? described.value.repositories : []).find((r) => r?.repositoryName === repository);
  if (!repo) {
    return absent('NotReturned');
  }
  const lifecycle = await read(aws, ['ecr', 'get-lifecycle-policy', '--registry-id', account, '--repository-name', repository], {
    notFound: ['LifecyclePolicyNotFoundException']
  });
  const policy = await read(aws, ['ecr', 'get-repository-policy', '--registry-id', account, '--repository-name', repository], {
    notFound: ['RepositoryPolicyNotFoundException']
  });
  const tags = typeof repo.repositoryArn === 'string' ? await read(aws, ['ecr', 'list-tags-for-resource', '--resource-arn', repo.repositoryArn]) : absent('NoArn');
  return present({
    arn: repo.repositoryArn ?? null,
    uri: repo.repositoryUri ?? null,
    registryId: repo.registryId ?? null,
    tagMutability: repo.imageTagMutability ?? null,
    tagMutabilityExclusions: Array.isArray(repo.imageTagMutabilityExclusionFilters) ? repo.imageTagMutabilityExclusionFilters.map((f) => String(f?.filter ?? '')) : [],
    scanOnPush: repo.imageScanningConfiguration?.scanOnPush === true,
    encryption: { type: repo.encryptionConfiguration?.encryptionType ?? null, kmsKey: repo.encryptionConfiguration?.kmsKey ?? null },
    lifecyclePolicy: lifecycle.state === 'present' ? present({ text: String(lifecycle.value.lifecyclePolicyText ?? '') }) : lifecycle,
    repositoryPolicy: policy.state === 'present' ? present({ text: String(policy.value.policyText ?? '') }) : policy,
    tags: tags.state === 'present' ? present(tagList(tags.value.tags)) : tags
  });
}

// -> result whose value is { registryId, scanType, rules: [{ frequency, filters: [{ filter, type }] }] }
export async function discoverRegistryScanning(aws) {
  const got = await read(aws, ['ecr', 'get-registry-scanning-configuration']);
  if (got.state !== 'present') {
    return got;
  }
  const config = got.value.scanningConfiguration ?? {};
  return present({
    registryId: got.value.registryId ?? null,
    scanType: config.scanType ?? null,
    rules: (Array.isArray(config.rules) ? config.rules : []).map((rule) => ({
      frequency: rule?.scanFrequency ?? null,
      filters: (Array.isArray(rule?.repositoryFilters) ? rule.repositoryFilters : []).map((f) => ({ filter: String(f?.filter ?? ''), type: f?.filterType ?? null }))
    }))
  });
}

// ECR WILDCARD filter: `*` matches any run of characters (including none);
// every other character is literal.
export function wildcardFilterMatches(filter, repository) {
  const body = filter
    .split('*')
    .map((part) => part.replace(/[\\^$.|+?()[\]{}]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${body}$`).test(repository);
}

const FREQUENCY_RANK = { MANUAL: 0, SCAN_ON_PUSH: 1, CONTINUOUS_SCAN: 2 };

// Which registry rule, if any, scans `repository` automatically?
//   -> { covered, scanType, frequency, rule, filter, basis, unsupported[] }
// BASIC supports SCAN_ON_PUSH (and MANUAL); ENHANCED supports SCAN_ON_PUSH and
// CONTINUOUS_SCAN (the higher frequency wins). MANUAL is not automatic
// coverage: the pipeline's poll would wait for a scan nobody starts. For BASIC,
// a repository-level scanOnPush (deprecated) still scans; ENHANCED ignores it.
export function scanningCoverage(scanning, repository, { repositoryScanOnPush = false } = {}) {
  const unsupported = [];
  let best = null;
  for (const [index, rule] of scanning.rules.entries()) {
    for (const f of rule.filters) {
      if (f.type !== 'WILDCARD') {
        unsupported.push(`rule ${index + 1} has filter type '${f.type}', which is not evaluated`);
        continue;
      }
      if (!wildcardFilterMatches(f.filter, repository)) {
        continue;
      }
      const allowed = scanning.scanType === 'ENHANCED' ? ['SCAN_ON_PUSH', 'CONTINUOUS_SCAN'] : ['SCAN_ON_PUSH', 'MANUAL'];
      if (!allowed.includes(rule.frequency)) {
        unsupported.push(`rule ${index + 1} has frequency '${rule.frequency}', which ${scanning.scanType} scanning does not use`);
        continue;
      }
      if (!best || FREQUENCY_RANK[rule.frequency] > FREQUENCY_RANK[best.frequency]) {
        best = { frequency: rule.frequency, rule: index + 1, filter: f.filter };
      }
    }
  }
  const automatic = best && best.frequency !== 'MANUAL';
  if (automatic) {
    return { covered: true, scanType: scanning.scanType, ...best, basis: 'registry-rule', unsupported };
  }
  if (scanning.scanType === 'BASIC' && repositoryScanOnPush) {
    return { covered: true, scanType: 'BASIC', frequency: 'SCAN_ON_PUSH', rule: null, filter: null, basis: 'repository-setting', unsupported };
  }
  return { covered: false, scanType: scanning.scanType, frequency: best?.frequency ?? null, rule: best?.rule ?? null, filter: best?.filter ?? null, basis: null, unsupported };
}
