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
//   - S3 exposes a FULL-OBJECT SHA-256 for that version (ChecksumType
//     FULL_OBJECT) and it equals the configured sha256. The configured digest
//     is never trusted on its own: no checksum, a COMPOSITE (multipart)
//     checksum or no checksum type all FAIL, so a break-glass change set is
//     created only for bytes S3 itself vouches for. S3's ChecksumSHA256 and
//     Lambda's CodeSha256 are both base64 of the raw digest, so one conversion
//     (codeSha256Of) serves both. SHA-256 is full-object only for a
//     single-part upload (multipart SHA-256 is always COMPOSITE): publish the
//     bundle with one PutObject and --checksum-algorithm SHA256.
//   After deployment, verify compares the live CodeSha256 to the same digest:
//   a second, independent check of what Lambda actually loaded.
import { describeError } from '../discover/result.mjs';
import { codeSha256Of } from './names.mjs';

const FAIL = 'FAIL';
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
      findings.push(f(FAIL, 'artifact-checksum-absent', `${where}: S3 stores no SHA-256 checksum for this version, so the configured sha256 cannot be compared with the object. Re-upload it in one PutObject with --checksum-algorithm SHA256`));
    } else if (head.value.checksumType !== 'FULL_OBJECT' || checksum.includes('-')) {
      findings.push(f(FAIL, 'artifact-checksum-not-full-object', `${where}: S3's SHA-256 is ${head.value.checksumType === 'COMPOSITE' || checksum.includes('-') ? 'a COMPOSITE (multipart) checksum' : `of checksum type ${head.value.checksumType ?? '(not reported)'}`}, not a full-object digest. Re-upload it in one PutObject with --checksum-algorithm SHA256`));
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
