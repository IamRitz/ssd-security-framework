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

const MAX_RULES = 2;
const MAX_FILTERS_PER_RULE = 100;

// Pure. The registry scanning configuration that would cover `repository`,
// built as CURRENT RULES + ONE FILTER — never a replacement:
//   - the scan type is never changed (BASIC stays BASIC, ENHANCED stays ENHANCED);
//   - every existing rule and filter is kept, in order, unchanged;
//   - the filter is appended to the existing SCAN_ON_PUSH rule, else (ENHANCED)
//     to the CONTINUOUS_SCAN rule, else a new SCAN_ON_PUSH rule is added.
// -> { changed: false, coverage }                   already covered by a rule
//    { changed: true, proposed, added, coverage }   proposed = { scanType, rules }
//    { changed: false, impossible: reason }         cannot be expressed safely
// Phase 2B only REPORTS this proposal (delivery.registryScanning existing);
// nothing applies it.
export function mergeScanningRules(scanning, repository) {
  if (!['BASIC', 'ENHANCED'].includes(scanning.scanType)) {
    return { changed: false, impossible: `the registry scan type is ${scanning.scanType ?? 'missing'}, so no rule can be proposed` };
  }
  const coverage = scanningCoverage(scanning, repository);
  if (coverage.covered && coverage.basis === 'registry-rule') {
    return { changed: false, coverage };
  }
  const rules = scanning.rules.map((rule) => ({ frequency: rule.frequency, filters: rule.filters.map((f) => ({ filter: f.filter, type: f.type })) }));
  const added = { filter: repository, type: 'WILDCARD' };
  const preferred = scanning.scanType === 'ENHANCED' ? ['SCAN_ON_PUSH', 'CONTINUOUS_SCAN'] : ['SCAN_ON_PUSH'];
  for (const frequency of preferred) {
    const rule = rules.find((r) => r.frequency === frequency);
    if (rule) {
      if (rule.filters.length >= MAX_FILTERS_PER_RULE) {
        return { changed: false, impossible: `the ${frequency} rule already has ${MAX_FILTERS_PER_RULE} filters (the ECR maximum)` };
      }
      rule.filters.push(added);
      return { changed: true, proposed: { scanType: scanning.scanType, rules }, added: { ...added, frequency }, coverage };
    }
  }
  if (rules.length >= MAX_RULES) {
    return { changed: false, impossible: `the registry already has ${MAX_RULES} rules (the ECR maximum) and none scans automatically for ${scanning.scanType}` };
  }
  rules.push({ frequency: 'SCAN_ON_PUSH', filters: [added] });
  return { changed: true, proposed: { scanType: scanning.scanType, rules }, added: { ...added, frequency: 'SCAN_ON_PUSH' }, coverage };
}
