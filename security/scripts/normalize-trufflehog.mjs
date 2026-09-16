import { readFile, rm, writeFile } from 'node:fs/promises';

const [inputPath, outputPath] = process.argv.slice(2);

if (!inputPath || !outputPath) {
  throw new Error('usage: normalize-trufflehog.mjs <input.jsonl> <output.json>');
}

let rawReport;

try {
  rawReport = await readFile(inputPath, 'utf8');
} finally {
  await rm(inputPath, { force: true });
}

const findings = rawReport
  .split('\n')
  .filter((line) => line.trim() !== '')
  .map((line) => JSON.parse(line))
  .map((finding) => {
    const sanitized = { ...finding };

    delete sanitized.Raw;
    delete sanitized.RawV2;
    delete sanitized.ExtraData;

    return sanitized;
  });

await writeFile(outputPath, `${JSON.stringify(findings, null, 2)}\n`, {
  mode: 0o600
});
