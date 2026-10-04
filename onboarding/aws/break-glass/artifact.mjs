// The published Lambda artifact contract (Phase 3C), checked identically by
// `aws plan --scope break-glass` (which blocks on any FAIL) and `aws verify
// --scope break-glass`.
//
// ssd-onboard never builds or uploads the artifact: publishing a
// deterministic bundle is a separate, prerequisite step. What is required of
// the object the operator config names:
//   - it exists as exactly that object VERSION (immutable: a later upload to
//     the same key is a different version and changes nothing deployed);
//   - its bucket has versioning Enabled (never Suspended), a public access
//     block with all four settings on, and no public bucket policy;
//   - when S3 holds a full-object SHA-256 checksum for the version, it equals
//     the configured sha256. When it holds none (or a composite multipart
//     checksum), that is NOT VERIFIED here — the authoritative comparison is
//     verify's: the deployed function's CodeSha256 against the same digest.
import { describeError } from '../discover/result.mjs';
import { codeSha256Of } from './names.mjs';

const FAIL = 'FAIL';
const NOT_VERIFIED = 'NOT VERIFIED';
const f = (severity, kind, message) => ({ severity, kind, message });
const PUBLIC_ACCESS_SETTINGS = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'];

// discovered: discoverArtifact() result. -> { findings[], observed[] }
export function artifactFindings(discovered, artifact) {
  const findings = [];
  const observed = [];
  const where = `s3://${artifact.bucket}/${artifact.key} version ${artifact.versionId}`;
  const { head, versioning, publicAccess, policyStatus } = discovered;

  if (head.state !== 'present') {
    findings.push(f(FAIL, 'artifact-unreadable', `${where} could not be read (${head.state === 'unverified' ? describeError(head) : head.code}): the template would pin an object version that is not proven to exist`));
  } else {
    observed.push(`object version ${head.value.versionId ?? '(none reported)'}, ${head.value.contentLength ?? '?'} bytes`);
    if (head.value.versionId !== artifact.versionId) {
      findings.push(f(FAIL, 'artifact-version-mismatch', `${where}: S3 answered version ${head.value.versionId ?? '(none)'}, not the configured one`));
    }
    const expected = codeSha256Of(artifact.sha256);
    const checksum = head.value.checksumSha256;
    if (typeof checksum !== 'string') {
      findings.push(f(NOT_VERIFIED, 'artifact-checksum-absent', `${where}: S3 stores no SHA-256 checksum for this version, so the configured sha256 is proven only by aws verify (live CodeSha256)`));
    } else if (head.value.checksumType === 'COMPOSITE' || checksum.includes('-')) {
      findings.push(f(NOT_VERIFIED, 'artifact-checksum-composite', `${where}: S3 holds a composite (multipart) checksum, which is not a digest of the object; the sha256 is proven only by aws verify`));
    } else if (checksum !== expected) {
      findings.push(f(FAIL, 'artifact-digest-mismatch', `${where}: S3's SHA-256 is ${checksum}, but the configured sha256 is ${artifact.sha256} (base64 ${expected})`));
    } else {
      observed.push(`S3 SHA-256 ${checksum} = configured sha256`);
    }
  }

  if (versioning.state !== 'present') {
    findings.push(f(FAIL, 'bucket-versioning-unverified', `bucket ${artifact.bucket}: versioning could not be read (${versioning.state === 'unverified' ? describeError(versioning) : versioning.code})`));
  } else {
    observed.push(`bucket versioning ${versioning.value.status ?? 'never enabled'}`);
    if (versioning.value.status !== 'Enabled') {
      findings.push(f(FAIL, 'bucket-not-versioned', `bucket ${artifact.bucket}: versioning is ${versioning.value.status ?? 'never enabled'}; the artifact bucket must keep every version (Enabled)`));
    }
  }

  if (publicAccess.state === 'absent') {
    findings.push(f(FAIL, 'bucket-public-access', `bucket ${artifact.bucket} has no public access block; all four settings must be on`));
  } else if (publicAccess.state !== 'present') {
    findings.push(f(FAIL, 'bucket-public-access-unverified', `bucket ${artifact.bucket}: the public access block could not be read (${describeError(publicAccess)})`));
  } else {
    const off = PUBLIC_ACCESS_SETTINGS.filter((k) => publicAccess.value[k] !== true);
    observed.push(`public access block: ${off.length === 0 ? 'all on' : `off: ${off.join(', ')}`}`);
    if (off.length > 0) {
      findings.push(f(FAIL, 'bucket-public-access', `bucket ${artifact.bucket}: public access block settings off: ${off.join(', ')}`));
    }
  }

  if (policyStatus.state === 'unverified') {
    findings.push(f(FAIL, 'bucket-policy-unverified', `bucket ${artifact.bucket}: whether its policy is public could not be read (${describeError(policyStatus)})`));
  } else if (policyStatus.state === 'present' && policyStatus.value.isPublic !== false) {
    findings.push(f(FAIL, 'bucket-public', `bucket ${artifact.bucket}: its bucket policy is ${policyStatus.value.isPublic === true ? 'PUBLIC' : 'of unknown status'}`));
  } else {
    observed.push(policyStatus.state === 'absent' ? 'no bucket policy' : 'bucket policy not public');
  }
  return { findings, observed };
}
