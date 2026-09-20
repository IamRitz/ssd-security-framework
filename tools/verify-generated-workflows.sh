#!/usr/bin/env bash
# Renders every ssd-onboard profile variant and proves the output is valid
# GitHub Actions, independently of ssd-onboard's own parser:
#
#   1. actionlint (pinned by digest) over every generated workflow and the examples
#   2. PyYAML parses every generated workflow to the same structure as the
#      strict subset parser the tests assert against (skipped, and said so, when
#      PyYAML is unavailable)
#
# Requires docker for actionlint.
set -euo pipefail

FRAMEWORK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ACTIONLINT_IMAGE='rhysd/actionlint@sha256:887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9' # 1.7.7

cd "$FRAMEWORK"
node --input-type=module - "$WORK" <<'JS'
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { renderAll } from './onboarding/lib/render.mjs';
import { config } from './test/support/onboarding-fixtures.mjs';

const out = process.argv[2];
const enforcing = { rollout: { gateMode: 'enforce' }, semgrep: { baseline: { state: 'accepted' } } };
const extras = {
  notifications: { slack: { enabled: true, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } }
};
const variants = [];
for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
  variants.push([`${profile}-onboarding`, config(profile)]);
  variants.push([`${profile}-enforcing`, config(profile, enforcing)]);
  variants.push([`${profile}-full`, config(profile, { ...enforcing, ...extras, ...(profile.includes('ecr') ? { delivery: { environment: 'production' } } : {}) })]);
}
for (const [name, c] of variants) {
  for (const file of renderAll(c).filter((f) => f.kind === 'workflow')) {
    const path = join(out, name, file.path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, file.content);
  }
}
console.log(`rendered ${variants.length} variants`);
JS

fail=0
echo "== actionlint (${ACTIONLINT_IMAGE#*@}) =="
for dir in "$WORK"/*/; do
  mapfile -t files < <(cd "$dir" && find .github/workflows -name '*.y*ml' | sort)
  if docker run --rm -v "$dir:/repo:ro" -w /repo "$ACTIONLINT_IMAGE" -no-color -oneline "${files[@]}"; then
    echo "  ok   $(basename "$dir") (${#files[@]} workflow(s))"
  else
    echo "  FAIL $(basename "$dir")" >&2
    fail=1
  fi
done
if docker run --rm -v "$FRAMEWORK/examples:/repo/examples:ro" -w /repo "$ACTIONLINT_IMAGE" -no-color -oneline examples/*/*.yml; then
  echo "  ok   examples"
else
  echo "  FAIL examples" >&2
  fail=1
fi

echo "== PyYAML equivalence =="
if python3 -c 'import yaml' 2>/dev/null; then
  find "$WORK" -name '*.yml' -print0 | xargs -0 node --input-type=module -e '
    import { readFileSync } from "node:fs";
    import { execFileSync } from "node:child_process";
    import { parseYaml } from "./onboarding/lib/yaml.mjs";
    const norm = (v) => Array.isArray(v) ? v.map(norm) : v && typeof v === "object"
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])])) : typeof v === "number" ? String(v) : v;
    const py = "import yaml,json,sys\nd=yaml.safe_load(open(sys.argv[1]))\nif True in d: d[\"on\"]=d.pop(True)\nprint(json.dumps(d))";
    let bad = 0;
    for (const file of process.argv.slice(1)) {
      const mine = JSON.stringify(norm(parseYaml(readFileSync(file, "utf8"))));
      const theirs = JSON.stringify(norm(JSON.parse(execFileSync("python3", ["-c", py, file]).toString())));
      if (mine !== theirs) { bad += 1; console.error("  DIFFERS " + file); }
    }
    console.log(`  ${process.argv.length - 1 - bad}/${process.argv.length - 1} generated workflows parse identically`);
    process.exitCode = bad ? 1 : 0;
  ' || fail=1
else
  echo "  skipped: PyYAML is not installed (actionlint above is the independent parser)"
fi

[ "$fail" -eq 0 ] && echo "ALL GENERATED WORKFLOWS VALID." || { echo "GENERATED WORKFLOW CHECK FAILED" >&2; exit 1; }
