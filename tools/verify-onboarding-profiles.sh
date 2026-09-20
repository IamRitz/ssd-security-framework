#!/usr/bin/env bash
# Exercises the four consumer capability profiles the framework claims to serve,
# and — most importantly — walks a brand-new library repository all the way from
# NO Semgrep baseline to a normally-gated one.
#
# The bootstrap deadlock (gate needs a baseline -> reports untrusted -> generator
# refuses) is the thing that blocks a first real consumer, so it is proven here
# end to end rather than only in unit tests.
#
# Scanner OUTPUT is taken from the framework's fixtures rather than by running
# Semgrep/Trivy locally: this exercises the framework's own logic and file
# contracts, not the scanners', which CI covers by actually running them.
#
# The gate and generator are invoked with RELATIVE report paths, exactly as the
# workflows invoke them, so this also proves those paths resolve against the
# consumer's working directory. Only the assertions use absolute paths.
set -euo pipefail

FRAMEWORK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TOOLKIT="$WORK/runner-temp/ssd-toolkit"
FIXTURES="$FRAMEWORK/security/scripts/__fixtures__"
RULESETS="p/owasp-top-ten p/javascript"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

mkdir -p "$(dirname "$TOOLKIT")"
cp -r "$FRAMEWORK" "$TOOLKIT"
rm -rf "$TOOLKIT/.git"
GATE="$TOOLKIT/security/scripts/security-gate.mjs"
GEN="$TOOLKIT/security/scripts/generate-semgrep-baseline.mjs"
CONF="$TOOLKIT/security/scripts/conformance.mjs"
POLICY="$TOOLKIT/security/policy.yaml"

new_consumer() {
  local dir="$1"
  mkdir -p "$dir/src" "$dir/reports"
  echo '{ "name": "c", "version": "1.0.0", "private": true }' > "$dir/package.json"
  echo 'export const hello = () => "hello";' > "$dir/src/app.js"
  cp "$FIXTURES"/clean/gitleaks.json "$FIXTURES"/clean/trufflehog.json \
     "$FIXTURES"/clean/osv-scanner.json "$dir/reports/"
  cp "$FIXTURES/new-high-sast/semgrep.json" "$dir/reports/semgrep.json"
}

# Absolute path in, dotted field out.
field() { node -e 'const r=require(process.argv[1]);const p=process.argv[2].split(".");let v=r;for(const k of p)v=v?.[k];process.stdout.write(String(v))' "$1" "$2"; }

echo "=============================================================="
echo " PROFILE 1 — library, no AWS: onboarding from NO baseline"
echo "=============================================================="
C="$WORK/library"; new_consumer "$C"; cd "$C"
RPT="$C/reports"
BASELINE="$C/security/baseline/semgrep-baseline.json"
mkdir -p "$(dirname "$BASELINE")"

echo "-- 1a. a missing baseline WITHOUT bootstrap must stay fail-closed"
node "$GATE" --policy "$POLICY" --baseline "$BASELINE" >/dev/null 2>&1 || true
[ "$(field "$RPT/security-gate.json" verdict)" = "BLOCK" ] || fail "expected BLOCK"
[ "$(field "$RPT/security-gate.json" integrity.trusted)" = "false" ] || fail "expected untrusted"
pass "missing baseline is a report-integrity BLOCK (case B stays closed)"

echo "-- 1b. the SAME state WITH bootstrap is trusted and auditable"
node "$GATE" --policy "$POLICY" --baseline "$BASELINE" --bootstrap >/dev/null 2>&1 || true
[ "$(field "$RPT/security-gate.json" integrity.trusted)" = "true" ] || fail "bootstrap run not trusted"
[ "$(field "$RPT/security-gate.json" bootstrap.active)" = "true" ] || fail "bootstrap not recorded"
pass "bootstrap run is trusted, and records why in the gate result"

echo "-- 1c. generate the first baseline from that run"
node "$GEN" --report reports/semgrep.json --gate reports/security-gate.json \
  --rulesets "$RULESETS" --output reports/semgrep-baseline.candidate.json 2>/dev/null
count="$(node -e 'process.stdout.write(String(require(process.argv[1]).findings.length))' "$RPT/semgrep-baseline.candidate.json")"
[ "$count" -ge 1 ] || fail "candidate baseline accepted no findings"
node -e '
  const b = require(process.argv[1]);
  if (b.schemaVersion !== 1) throw new Error("bad schemaVersion");
  if (!Array.isArray(b.rulesets) || b.rulesets.length !== 2) throw new Error("rulesets not recorded");
  for (const f of b.findings) if (!/^[0-9a-f]{64}$/.test(f.fingerprint)) throw new Error("bad fingerprint");
' "$RPT/semgrep-baseline.candidate.json"
pass "candidate baseline: $count finding(s), rulesets recorded, sha256 fingerprints"

echo "-- 1d. commit it, then run the gate NORMALLY"
cp "$RPT/semgrep-baseline.candidate.json" "$BASELINE"
node "$GATE" --policy "$POLICY" --baseline "$BASELINE" >/dev/null 2>&1 || true
[ "$(field "$RPT/security-gate.json" verdict)" = "PASS" ] || fail "expected PASS after baselining"
[ "$(field "$RPT/security-gate.json" bootstrap.active)" = "false" ] || fail "normal run should not be bootstrap"
state="$(node -e 'process.stdout.write(require(process.argv[1]).findings.find(f=>f.source==="semgrep").baselineState)' "$RPT/security-gate.json")"
[ "$state" = "existing" ] || fail "finding should now be baseline-known, got $state"
pass "normal gate run PASSes; the backlog logs instead of blocking"

echo "-- 1e. bootstrap REFUSES to run again now a baseline exists"
node "$GATE" --policy "$POLICY" --baseline "$BASELINE" --bootstrap >/dev/null 2>&1 || true
reason="$(field "$RPT/security-gate.json" findings.0.reason)"
grep -q 'bootstrap refused' <<<"$reason" || fail "second bootstrap was not refused: $reason"
pass "a repo that already has a baseline cannot be re-bootstrapped"

echo "-- 1f. conformance: library requires only source controls"
node "$CONF" --artifact-type library --registry none --deploy-target none --phase pr \
  --break-glass false \
  --observed '{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"}}' \
  --output reports/conformance.json >/dev/null
node -e '
  const r = require(process.argv[1]); const s = r.summary;
  if (s.requiredByRepository !== 4) throw new Error(`required=${s.requiredByRepository}, expected 4`);
  if (s.applied !== 4 || s.failed !== 0 || s.deferred !== 0) throw new Error(JSON.stringify(s));
  console.log(`     required=${s.requiredByRepository} applied=${s.applied} N/A=${s.notApplicable} deferred=${s.deferred}`);
' "$RPT/conformance.json"
pass "no AWS, no image, no deploy required — and nothing deferred"

echo "-- 1g. scanners succeed, policy BLOCKs: 3 scanning controls applied, the gate failed"
# The live-run regression: evidence is per control, so a BLOCK verdict fails the
# source-gate control and nothing else.
cp "$FIXTURES/live-python-source-only/osv-scanner.json" reports/osv-scanner.json
cp "$FIXTURES/live-python-source-only/pip-audit.json" reports/pip-audit.json
echo 'requests==2.32.5' > requirements.txt
node "$GATE" --policy "$POLICY" --baseline "$BASELINE" >/dev/null 2>&1 || true
[ "$(field "$RPT/security-gate.json" verdict)" = "BLOCK" ] || fail "expected a policy BLOCK from the live OSV report"
[ "$(field "$RPT/security-gate.json" integrity.trusted)" = "true" ] || fail "a policy BLOCK must not be an integrity failure"
[ "$(field "$RPT/security-gate.json" correlation.summary.issues)" -lt "$(field "$RPT/security-gate.json" correlation.summary.rawFindings)" ] \
  || fail "aliased OSV records were not correlated into fewer developer issues"
SECRET_SCAN_JOB_RESULT=success DEPENDENCY_SCAN_JOB_RESULT=success SAST_JOB_RESULT=success GITHUB_OUTPUT="$RPT/controls.out" \
  node "$TOOLKIT/security/scripts/source-control-results.mjs" --gate reports/security-gate.json >/dev/null
grep -qx 'dependency_scan_result=success' "$RPT/controls.out" || fail "a scanner that found vulnerabilities was not reported as a successful scan"
node "$CONF" --artifact-type library --registry none --deploy-target none --phase pr \
  --break-glass false \
  --observed '{"secret-scan":{"status":"success"},"dependency-scan":{"status":"success"},"sast":{"status":"success"},"source-gate":{"status":"failure","verdict":"BLOCK","integrity_trusted":"true"}}' \
  --output reports/conformance-block.json >/dev/null 2>&1 || true
node -e '
  const r = require(process.argv[1]); const s = r.summary;
  if (s.applied !== 3 || s.failed !== 1) throw new Error(JSON.stringify(s));
  const gate = r.controls.find((c) => c.id === "source-gate");
  if (!/returned a blocking result/.test(gate.reason)) throw new Error(gate.reason);
  console.log(`     applied=${s.applied} failed=${s.failed}: ${gate.reason}`);
' "$RPT/conformance-block.json"
cp "$FIXTURES"/clean/osv-scanner.json reports/osv-scanner.json
rm -f requirements.txt reports/pip-audit.json
pass "a finding is not a scanner failure: only the source gate control failed"
echo

echo "=============================================================="
echo " PROFILE 2 — library WITH break glass (no delivery AWS)"
echo "=============================================================="
node "$CONF" --artifact-type library --registry none --deploy-target none --phase pr \
  --break-glass true --strict-break-glass-evidence true \
  --observed '{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"},"break-glass":{"status":"skipped","decision":"","request_delivered":"","gate_digest":"","delegated":"false"}}' \
  --output reports/conformance-bg.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  const get = (id) => r.controls.find((c) => c.id === id);
  if (get("break-glass").status !== "applied") throw new Error("break-glass should be applied");
  for (const id of ["registry-scan-collect","artifact-gate","gated-deploy"])
    if (get(id).status !== "not-applicable") throw new Error(`${id} should be N/A`);
  if (r.summary.failed !== 0) throw new Error("unexpected failures");
  console.log(`     break-glass applied; delivery controls N/A; failed=${r.summary.failed}`);
' "$RPT/conformance-bg.json"
pass "only the narrow break-glass invoker path adds AWS; no delivery AWS required"
echo

echo "=============================================================="
echo " PROFILE 3 — self-managed container (no framework registry/deploy)"
echo "=============================================================="
node "$CONF" --artifact-type container --registry none --deploy-target self-managed --phase pr \
  --break-glass false \
  --observed '{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"},"image-scan-prepush":{"status":"pass"}}' \
  --output reports/conformance-self.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  const get = (id) => r.controls.find((c) => c.id === id);
  if (get("image-scan-prepush").status !== "applied") throw new Error("pre-push image scan must still apply");
  for (const id of ["registry-scan-collect","artifact-gate","gated-deploy"]) {
    const c = get(id);
    if (c.status !== "not-applicable") throw new Error(`${id} is ${c.status}, expected not-applicable`);
  }
  if (r.summary.deferred !== 0) throw new Error("nothing should be deferred to a run that never happens");
  if (r.summary.failed !== 0) throw new Error("unexpected failures");
  console.log(`     image gate applied; registry/deploy N/A; deferred=${r.summary.deferred}`);
' "$RPT/conformance-self.json"
pass "pre-push image gate still required; framework registry/deploy correctly N/A"
echo

echo "=============================================================="
echo " PROFILE 4 — full framework-gated container (PR vs delivery)"
echo "=============================================================="
PR_OBSERVED='{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"},"image-scan-prepush":{"status":"pass"},"break-glass":{"status":"skipped","decision":"","request_delivered":"","gate_digest":"","delegated":"false"}}'

echo "-- 4a. PR phase defers the delivery controls (never a fake pass)"
node "$CONF" --artifact-type container --registry ecr --deploy-target framework-gated --phase pr \
  --break-glass true --strict-break-glass-evidence true --observed "$PR_OBSERVED" --output reports/conf-pr.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  const get = (id) => r.controls.find((c) => c.id === id);
  for (const id of ["registry-scan-collect","artifact-gate","gated-deploy"]) {
    const c = get(id);
    if (c.status !== "deferred") throw new Error(`${id} is ${c.status}, expected deferred`);
    if (c.appliesToRepository !== true) throw new Error(`${id} must still be required`);
  }
  if (r.summary.failed !== 0) throw new Error("deferred must not be a failure");
  console.log(`     required=${r.summary.requiredByRepository} applied=${r.summary.applied} deferred=${r.summary.deferred} failed=${r.summary.failed}`);
' "$RPT/conf-pr.json"
pass "delivery controls deferred: required by the repo, proven by the delivery run"

echo "-- 4b. a caller claiming a deploy passed on a PR is NOT honoured"
node "$CONF" --artifact-type container --registry ecr --deploy-target framework-gated --phase pr \
  --break-glass true --strict-break-glass-evidence true \
  --observed '{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"},"image-scan-prepush":{"status":"pass"},"break-glass":{"status":"skipped","decision":"","request_delivered":"","gate_digest":"","delegated":"false"},"gated-deploy":{"status":"pass","evidence":"runs on push to main"}}' \
  --output reports/conf-fake.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  const c = r.controls.find((x) => x.id === "gated-deploy");
  if (c.status !== "deferred") throw new Error(`fabricated pass was honoured: ${c.status}`);
  if (!r.warnings.some((w) => /gated-deploy/.test(w) && /did not execute/.test(w)))
    throw new Error("no warning for a fabricated result");
  console.log("     claim rejected, and surfaced as a warning");
' "$RPT/conf-fake.json"
pass "a control that did not execute cannot have passed"

echo "-- 4c. delivery phase proves them with real job results"
node "$CONF" --artifact-type container --registry ecr --deploy-target framework-gated --phase delivery \
  --break-glass true --strict-break-glass-evidence true \
  --observed '{"secret-scan":{"status":"success"},"dependency-scan":{"status":"success"},"sast":{"status":"success"},"source-gate":{"status":"success"},"image-scan-prepush":{"status":"success"},"break-glass":{"status":"skipped","decision":"","request_delivered":"","gate_digest":"","delegated":"false"},"registry-scan-collect":{"status":"success","evidence":"ecr-collect"},"artifact-gate":{"status":"success","evidence":"artifact-gate"},"gated-deploy":{"status":"success","evidence":"digest-pinned SSM deploy"}}' \
  --output reports/conf-del.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  if (r.summary.deferred !== 0) throw new Error("nothing should be deferred in delivery");
  if (r.summary.failed !== 0) throw new Error("unexpected failures");
  if (r.summary.applied !== r.summary.requiredByRepository) throw new Error("not every required control proven");
  console.log(`     applied=${r.summary.applied}/${r.summary.requiredByRepository} deferred=0 failed=0`);
' "$RPT/conf-del.json"
pass "every required control proven in the delivery run"

echo "-- 4d. delivery phase FAILS when delivery evidence is missing"
node "$CONF" --artifact-type container --registry ecr --deploy-target framework-gated --phase delivery \
  --break-glass true --strict-break-glass-evidence true --observed "$PR_OBSERVED" --output reports/conf-del-missing.json >/dev/null 2>&1 || true
node -e '
  const r = require(process.argv[1]);
  if (r.summary.failed !== 3) throw new Error(`failed=${r.summary.failed}, expected 3`);
  console.log(`     failed=${r.summary.failed} (absence of evidence is not evidence)`);
' "$RPT/conf-del-missing.json"
pass "missing delivery evidence fails closed rather than deferring"
echo
echo "ALL PROFILES PASSED."
