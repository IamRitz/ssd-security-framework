// Renders `.github/workflows/_source-scan.yml` from `_source-security.yml`.
//
// Why a generated twin: GitHub validates a called workflow's job permissions
// statically, before any `if:` is evaluated, so the one `id-token: write` in
// `_source-security.yml`'s gate job forces EVERY caller to grant OIDC — even a
// repository with no break-glass at all. That file's in-job Lambda path is a
// published v1 contract and cannot be removed within v1. The OIDC-free twin
// gives new callers least privilege without a second, hand-maintained copy of
// the scanner logic: it is derived mechanically and the tests fail on any drift.
//
// The transformation is deliberately tiny and line-based:
//   # >>> legacy-only ... # <<< legacy-only   dropped (markers included)
//   # >>> scan-only   ... # <<< scan-only     each `# | text` line emitted as
//                                             `text` at the same indentation;
//                                             markers dropped
// Everything else is copied byte for byte.
//
//   node tools/render-source-scan.mjs          write the twin
//   node tools/render-source-scan.mjs --check  exit 1 if the committed twin is stale
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const SOURCE = join(ROOT, '.github/workflows/_source-security.yml');
export const TARGET = join(ROOT, '.github/workflows/_source-scan.yml');

const MARKER = /^(\s*)# (>>>|<<<) (legacy-only|scan-only)\s*$/;
const SCAN_LINE = /^(\s*)# \|(?: (.*))?$/;

export function renderSourceScan(source) {
  const out = [];
  let region = null;
  source.split('\n').forEach((line, index) => {
    const where = `line ${index + 1}`;
    const marker = MARKER.exec(line);
    if (marker) {
      const [, , direction, name] = marker;
      if (direction === '>>>') {
        if (region) throw new Error(`${where}: '${name}' opened inside '${region}'`);
        region = name;
      } else {
        if (region !== name) throw new Error(`${where}: '${name}' closed but '${region ?? 'nothing'}' is open`);
        region = null;
      }
      return;
    }
    if (region === 'legacy-only') return;
    if (region === 'scan-only') {
      const scan = SCAN_LINE.exec(line);
      if (!scan) throw new Error(`${where}: every scan-only line must be written as '# | text'`);
      out.push(scan[2] === undefined ? '' : `${scan[1]}${scan[2]}`);
      return;
    }
    out.push(line);
  });
  if (region) throw new Error(`unterminated '${region}' region`);
  return out.join('\n');
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  const rendered = renderSourceScan(readFileSync(SOURCE, 'utf8'));
  if (process.argv.includes('--check')) {
    let current = '';
    try {
      current = readFileSync(TARGET, 'utf8');
    } catch {
      // missing counts as stale
    }
    if (current !== rendered) {
      console.error('_source-scan.yml is stale: run `node tools/render-source-scan.mjs` and commit the result.');
      process.exit(1);
    }
    console.log('_source-scan.yml matches its source.');
  } else {
    writeFileSync(TARGET, rendered);
    console.log(`wrote ${TARGET}`);
  }
}
