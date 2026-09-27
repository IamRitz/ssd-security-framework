// Extracts the REAL `run:` script of a workflow step, so tests execute what the
// workflow runs rather than pattern-matching it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The `run:` body of the step named `name` in `file`, dedented.
export function stepScript(file, name) {
  const source = readFileSync(file, 'utf8');
  const start = source.indexOf(`- name: ${name}\n`);
  assert.ok(start >= 0, `${file}: step "${name}" not found`);
  const stepIndent = source.lastIndexOf('\n', start) + 1;
  const indent = start - stepIndent;
  const lines = source.slice(start).split('\n').slice(1);
  const body = [];
  let runIndent = null;
  for (const line of lines) {
    if (runIndent === null) {
      // Stop at the next step or the end of the job.
      if (line.trim() !== '' && line.length - line.trimStart().length <= indent) {
        break;
      }
      const match = /^(\s*)run: \|\s*$/.exec(line);
      if (match) {
        runIndent = match[1].length;
      }
      continue;
    }
    if (line.trim() !== '' && line.length - line.trimStart().length <= runIndent) {
      break;
    }
    body.push(line);
  }
  assert.ok(body.length > 0, `${file}: step "${name}" has no multi-line run script`);
  const dedent = Math.min(...body.filter((line) => line.trim() !== '').map((line) => line.length - line.trimStart().length));
  return body.map((line) => line.slice(dedent)).join('\n');
}
