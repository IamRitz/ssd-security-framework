# ECR enhanced scanning (Amazon Inspector) response fixtures

Source: the `ecr-raw-response` artifact of Deploy run `34744609758` (commit
`f947250`), the first run with the push+scan role able to read Inspector. The AWS
account ID is redacted to `123456789012`; everything else is as the API returned
it. The image digest is real.

## Live-captured (verbatim apart from the account ID)

| File | What it is |
| --- | --- |
| `complete-mixed.json` | The `COMPLETE` body: `enhancedFindings[6]` (1 CRITICAL, 4 HIGH, 1 MEDIUM, all `fixAvailable: "YES"`) **and** `findings: []` |
| `pending.json` | The `PENDING` body: `findings: []`, **no** `findingSeverityCounts`, no `enhancedFindings` |
| `scan-not-found.stderr.txt` | Attempt 1 stderr, 2s after push: `ScanNotFoundException` — retryable |
| `complete-before-findings.json` | **Run `34745111774`, attempt 2.** `status: COMPLETE` with `findings: []` and `imageScanCompletedAt`, but **no** `findingSeverityCounts` and no `enhancedFindings` — Inspector had not attached results yet. Not ready, not clean: the poller waits through it |
| `complete-clean.json` | **Run `34809100547`, attempt 40.** The same counts-less `COMPLETE` shape as `complete-before-findings.json`, for an image Inspector confirmed has zero findings. It never changed over 40 attempts (10m), so a clean enhanced scan omits `findingSeverityCounts`, `enhancedFindings`, and `vulnerabilitySourceUpdatedAt` permanently. The body alone cannot distinguish clean from not-yet-attached |
| `inspector-coverage-clean.json` | `inspector2 list-coverage` filtered by `resourceId` for that digest (captured 2026-09-14): `scanStatus INACTIVE/SCAN_FREQUENCY_SCAN_ON_PUSH`, `lastScannedAt` equal to ECR's `imageScanCompletedAt`. `list-findings` by `ecrImageHash` returned `findings: []` |
| `failed-open-regression.json` | Same body as `complete-mixed.json`, named for the incident it pins: the basic-only normalizer read `findings: []` and reported a clean scan |

## Derived (one stated change from the live body each)

| File | Change | Why derived |
| --- | --- | --- |
| `with-fix.json` | Kept only the CRITICAL finding; counts `{CRITICAL: 1}` | Isolate one case |
| `no-fix.json` | `with-fix.json` with `fixAvailable: "NO"`, every `fixedInVersion: "NotAvailable"` | **Not observed live** — every real finding had a fix |
| `empty-complete.json` | `enhancedFindings: []`, counts `{}` | **Not observed live, and contradicted by `complete-clean.json`:** the real clean body omits both keys. Kept as a defensive shape the normalizer must still handle |
| `malformed.json` | Truncated JSON | Synthetic |

Values assumed but not yet seen from this API, all handled fail-closed: `fixAvailable`
`"NO"`/`"PARTIAL"`, finding `status` other than `ACTIVE`, severity `UNTRIAGED`,
`fixedInVersion: "NotAvailable"`.
