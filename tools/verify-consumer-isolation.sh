#!/usr/bin/env bash
# Proves the claim the whole extraction rests on: a consumer repository needs
# ZERO framework files.
#
# It reproduces, on a local filesystem, exactly what the reusable workflows do on
# a runner: the consumer is the working directory, the toolkit lives somewhere
# else entirely (the runner puts it under $RUNNER_TEMP), and every script is
# invoked by absolute path from that other place while reports land in the
# consumer's own tree.
#
# If this passes, the only thing left that CI adds is `actions/checkout`.
set -euo pipefail

FRAMEWORK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CONSUMER="$WORK/consumer"
TOOLKIT="$WORK/runner-temp/ssd-toolkit"   # stands in for $RUNNER_TEMP/ssd-toolkit
FIXTURES="$FRAMEWORK/security/scripts/__fixtures__"

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

echo "framework: $FRAMEWORK"
echo "workdir:   $WORK"
echo

# --- 1. A consumer with no framework files whatsoever ----------------------
mkdir -p "$CONSUMER/src" "$CONSUMER/security/baseline"
cat > "$CONSUMER/package.json" <<'JSON'
{ "name": "scratch-consumer", "version": "1.0.0", "private": true, "type": "module" }
JSON
cat > "$CONSUMER/package-lock.json" <<'JSON'
{ "name": "scratch-consumer", "version": "1.0.0", "lockfileVersion": 3, "packages": {} }
JSON
echo 'export const hello = () => "hello";' > "$CONSUMER/src/app.js"
# The ONE security file a consumer owns: its own accepted-findings baseline.
cp "$FIXTURES/clean/semgrep-baseline.json" "$CONSUMER/security/baseline/semgrep-baseline.json"

# The toolkit is placed OUTSIDE the consumer, as the workflows do.
mkdir -p "$(dirname "$TOOLKIT")"
cp -r "$FRAMEWORK" "$TOOLKIT"
rm -rf "$TOOLKIT/.git"

echo "== 1. the consumer contains no framework files =="
strays="$(find "$CONSUMER" \( -name '_*.yml' -o -name '*-gate.mjs' -o -name 'conformance.mjs' \
  -o -name 'policy.yaml' -o -name 'detect-ecosystems.mjs' -o -name 'notify.mjs' \) -print)"
[ -z "$strays" ] || fail "framework files found in the consumer: $strays"
[ ! -d "$CONSUMER/security/scripts" ] || fail "consumer has a security/scripts directory"
pass "no framework workflows, scripts, or policy in the consumer tree"
echo "     consumer tree:"
(cd "$CONSUMER" && find . -type f | sort | sed 's/^/       /')
echo

# --- 2. ecosystem detection runs from the toolkit against the consumer ------
echo "== 2. toolkit scripts execute from outside the consumer =="
cd "$CONSUMER"
detect="$(node "$TOOLKIT/security/scripts/detect-ecosystems.mjs")"
grep -q 'npm (found package-lock.json)' <<<"$detect" || fail "npm ecosystem not detected: $detect"
pass "detect-ecosystems.mjs resolved the CONSUMER's manifests, not the toolkit's"

# --- 3. the gate writes into the consumer, using the framework's policy -----
mkdir -p "$CONSUMER/reports"
cp "$FIXTURES"/clean/gitleaks.json "$FIXTURES"/clean/trufflehog.json \
   "$FIXTURES"/clean/npm-audit.json "$FIXTURES"/clean/osv-scanner.json \
   "$FIXTURES"/clean/semgrep.json "$CONSUMER/reports/"

node "$TOOLKIT/security/scripts/security-gate.mjs" \
  --policy "$TOOLKIT/security/policy.yaml" \
  --baseline security/baseline/semgrep-baseline.json \
  >/dev/null
[ -f "$CONSUMER/reports/security-gate.json" ] || fail "gate result not written into the consumer"
verdict="$(node -e 'process.stdout.write(require(process.argv[1]).verdict)' "$CONSUMER/reports/security-gate.json")"
[ "$verdict" = "PASS" ] || fail "expected PASS, got $verdict"
trusted="$(node -e 'process.stdout.write(String(require(process.argv[1]).integrity.trusted))' "$CONSUMER/reports/security-gate.json")"
[ "$trusted" = "true" ] || fail "gate did not trust its own inputs"
pass "security-gate.mjs: policy from the toolkit, reports in the consumer, verdict $verdict"

# --- 4. the consumer is still framework-free afterwards ---------------------
strays="$(find "$CONSUMER" \( -name '_*.yml' -o -name '*-gate.mjs' -o -name 'policy.yaml' \) -print)"
[ -z "$strays" ] || fail "the run deposited framework files into the consumer: $strays"
pass "no framework file leaked into the consumer during the run"
echo

# --- 5. artifact_type=none reports image controls N/A, not failed ----------
echo "== 5. a consumer that ships no container =="
observed='{"secret-scan":{"status":"pass"},"dependency-scan":{"status":"pass"},"sast":{"status":"pass"},"source-gate":{"status":"pass"}}'
node "$TOOLKIT/security/scripts/conformance.mjs" \
  --artifact-type none --registry none --deploy-target none \
  --observed "$observed" --output reports/conformance.json >/dev/null
node -e '
  const r = require(process.argv[1]);
  const get = (id) => r.controls.find((c) => c.id === id);
  for (const id of ["image-scan-prepush", "registry-scan-collect", "artifact-gate"]) {
    const c = get(id);
    if (c.status !== "not-applicable") throw new Error(`${id} is ${c.status}, expected not-applicable`);
    if (!/artifact_type=none/.test(c.reason)) throw new Error(`${id} reason does not name the capability: ${c.reason}`);
  }
  if (r.summary.failed !== 0) throw new Error(`failed=${r.summary.failed}, expected 0`);
  if (get("source-gate").status !== "applied") throw new Error("source-gate should be applied");
  console.log(`     image controls N/A with reasons; failed=${r.summary.failed}, notApplicable=${r.summary.notApplicable}`);
' "$CONSUMER/reports/conformance.json"
pass "image controls reported N/A with a reason, and nothing failed"
echo

# --- 6. a Python-only consumer -------------------------------------------
echo "== 6. a Python-only consumer =="
PY="$WORK/py-consumer"
mkdir -p "$PY"
printf 'requests==2.31.0\n' > "$PY/requirements.txt"
cd "$PY"
pydetect="$(node "$TOOLKIT/security/scripts/detect-ecosystems.mjs")"
grep -q 'python (found requirements.txt)' <<<"$pydetect" || fail "python not detected: $pydetect"
grep -q 'npm: none' <<<"$pydetect" || fail "npm should not be detected: $pydetect"
pass "pip-audit target detected, npm audit cleanly skipped (OSV-Scanner still covers it)"
echo
echo "ALL CHECKS PASSED — a consumer repository needs no framework files."
