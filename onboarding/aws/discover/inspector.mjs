// Amazon Inspector state for enhanced ECR scanning. "Inspector is enabled" and
// "this repository is covered" are separate facts, read separately.
import { absent, present, read } from './result.mjs';

// -> result whose value is { accountState, ecrState }
export async function discoverInspectorAccount(aws, { account }) {
  const got = await read(aws, ['inspector2', 'batch-get-account-status', '--account-ids', account]);
  if (got.state !== 'present') {
    return got;
  }
  const entry = (Array.isArray(got.value.accounts) ? got.value.accounts : []).find((a) => a?.accountId === account);
  if (!entry) {
    return absent('NotReturned');
  }
  return present({ accountState: entry.state?.status ?? null, ecrState: entry.resourceState?.ecr?.status ?? null });
}

// -> result whose value is { records: [{ resourceId, resourceType, scanStatus, reason }] }
export async function discoverInspectorCoverage(aws, { repository }) {
  const filter = JSON.stringify({
    resourceType: [{ comparison: 'EQUALS', value: 'AWS_ECR_REPOSITORY' }],
    ecrRepositoryName: [{ comparison: 'EQUALS', value: repository }]
  });
  const got = await read(aws, ['inspector2', 'list-coverage', '--filter-criteria', filter]);
  if (got.state !== 'present') {
    return got;
  }
  return present({
    records: (Array.isArray(got.value.coveredResources) ? got.value.coveredResources : []).map((r) => ({
      resourceId: r?.resourceId ?? null,
      resourceType: r?.resourceType ?? null,
      scanStatus: r?.scanStatus?.statusCode ?? null,
      reason: r?.scanStatus?.reason ?? null
    }))
  });
}
