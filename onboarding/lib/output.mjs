// Human-readable output for ssd-onboard: one status vocabulary, one small block
// model, one formatter. Machine output (--json) never passes through here.
//
// TRUST: much of what reaches the terminal is repository-controlled — paths,
// manifest names, scanner messages, config values, diffs of hand-edited files.
// format() therefore SANITIZES every string a block carries before it styles
// anything: terminal control characters (ESC/CSI/OSC, BEL, CR, C1, bidi
// overrides) are rendered as visible escapes such as \x1b, \r or \u202e (U+202E), so an
// injection attempt is shown rather than executed or silently dropped. ANSI is
// only ever added afterwards, around text the formatter itself produced.
//
// Commands build a list of blocks (heading, section, rows, text, command, diff)
// and hand it to format(); nothing else in the CLI emits ANSI.

// --- sanitization -----------------------------------------------------------------

const hex = (code, width) => code.toString(16).padStart(width, '0');

// C0 controls except TAB and LF, DEL, C1 controls, and the Unicode characters
// that reorder or break lines on display (Trojan Source-style bidi overrides).
const UNSAFE_RANGES = [
  [0x00, 0x08], // C0, except TAB (0x09) and LF (0x0a)
  [0x0b, 0x1f], // ... including CR and ESC
  [0x7f, 0x9f], // DEL and C1 (0x9b is a one-byte CSI)
  [0x061c, 0x061c], // ARABIC LETTER MARK
  [0x200e, 0x200f], // LRM, RLM
  [0x2028, 0x2029], // LINE / PARAGRAPH SEPARATOR
  [0x202a, 0x202e], // bidi embeddings and overrides
  [0x2066, 0x2069] // bidi isolates
];
const UNSAFE = new RegExp(`[${UNSAFE_RANGES.map(([a, b]) => `\\u${hex(a, 4)}-\\u${hex(b, 4)}`).join('')}]`, 'g');

function escapeChar(ch) {
  if (ch === '\r') {
    return '\\r';
  }
  const code = ch.charCodeAt(0);
  return code < 0x80 ? `\\x${hex(code, 2)}` : `\\u${hex(code, 4)}`;
}

// Text with every terminal control character made visible. LF is kept (it is
// structure: format() indents continuation lines under their owner) unless
// `singleLine`, which also escapes it — for labels such as paths, where a
// newline could fake a row of its own.
export function sanitize(value, { singleLine = false } = {}) {
  const text = String(value ?? '').replace(UNSAFE, escapeChar);
  return singleLine ? text.replace(/\n/g, '\\n') : text;
}

// --- style ------------------------------------------------------------------------

const SGR = { bold: [1, 22], dim: [2, 22], red: [31, 39], green: [32, 39], yellow: [33, 39], cyan: [36, 39] };

export const PLAIN = Object.freeze({ color: false, width: 100 });

// Color only for an interactive terminal: never for a redirected or injected
// stream, never with NO_COLOR (https://no-color.org: set and non-empty) and
// never on TERM=dumb. Width is read only from a TTY, so non-interactive output
// is identical wherever it runs.
export function outputStyle(stream, env = process.env) {
  const tty = Boolean(stream?.isTTY);
  const color = tty && !env.NO_COLOR && env.TERM !== 'dumb';
  const width = tty && Number.isInteger(stream.columns) && stream.columns > 0 ? stream.columns : PLAIN.width;
  return { color, width };
}

// `text` is already sanitized; tones are the formatter's own decision.
function paint(style, tones, text) {
  if (!style.color || text === '') {
    return text;
  }
  return tones.reduce((acc, tone) => `\x1b[${SGR[tone][0]}m${acc}\x1b[${SGR[tone][1]}m`, text);
}

// --- vocabulary -------------------------------------------------------------------

// Check statuses: the symbol and the word always appear together, so color is
// never the only signal. The words are the machine statuses, verbatim.
export const STATUS = Object.freeze({
  PASS: { symbol: '✓', tone: 'green' },
  WARN: { symbol: '!', tone: 'yellow' },
  FAIL: { symbol: '✗', tone: 'red' },
  'NOT VERIFIED': { symbol: '?', tone: 'yellow' },
  BLOCK: { symbol: '✗', tone: 'red' }
});
const STATUS_WIDTH = Math.max(...Object.keys(STATUS).map((word) => word.length));

// Overall results. The doctor outcomes are its JSON `outcome` values, verbatim;
// `aws doctor` maps its JSON outcomes onto these words (aws/report.mjs).
export const OUTCOME = Object.freeze({
  READY: 'PASS',
  'READY WITH WARNINGS': 'WARN',
  BLOCKED: 'FAIL',
  'READY (LOCAL CHECKS)': 'PASS',
  'NOT READY': 'FAIL',
  'NOT VERIFIED': 'NOT VERIFIED',
  // `aws apply`: only an observed, successful stack operation is a pass;
  // REFUSED, ERROR and APPLY FAILED fall through to FAIL.
  APPLIED: 'PASS',
  // `aws verify` (aws/verify-report.mjs)
  VERIFIED: 'PASS',
  'VERIFIED WITH WARNINGS': 'WARN',
  FAILED: 'FAIL'
});

// Generated-file plan actions (files.mjs) and stale files.
export const FILE_STATE = Object.freeze({
  create: { symbol: '+', word: 'create', tone: null },
  update: { symbol: '~', word: 'update', tone: null },
  unchanged: { symbol: '=', word: 'unchanged', tone: 'dim' },
  adopted: { symbol: '~', word: 'adopt', tone: 'yellow' },
  forced: { symbol: '!', word: 'overwrite', tone: 'yellow' },
  conflict: { symbol: '!', word: 'conflict', tone: 'red' },
  stale: { symbol: '-', word: 'stale', tone: 'yellow' }
});
const FILE_WIDTH = Math.max(...Object.values(FILE_STATE).map((s) => s.word.length)) + 1;

// An unknown status must never look like a pass.
const statusOf = (word) => STATUS[word] ?? { symbol: '?', tone: 'red' };

// --- blocks -----------------------------------------------------------------------

// Bodies may hold arrays and `false` placeholders (conditional blocks).
const children = (body) => body.flat(Infinity).filter(Boolean);

export const heading = (title, ...notes) => ({ kind: 'heading', title, notes: notes.filter(Boolean) });
export const section = (title, ...body) => ({ kind: 'section', title, body: children(body) });
// Indented body without a title (details under a row).
export const group = (...body) => ({ kind: 'group', body: children(body) });
// Free text; each string may span lines. tone: 'dim' for secondary prose.
export const text = (lines, { tone = null } = {}) => ({ kind: 'text', lines: [lines].flat(), tone });
export const dim = (lines) => text(lines, { tone: 'dim' });
// A command to copy: indented, never wrapped.
export const command = (lines) => ({ kind: 'command', lines: [lines].flat() });
// A unified diff, shown line for line.
export const diff = (body) => ({ kind: 'diff', body });
export const blank = () => ({ kind: 'blank' });

// rows([row(...), ...], { words }) — an aligned label/value table. `words`
// prints the status word next to its symbol (doctor-style).
export const rows = (items, { words = false } = {}) => ({ kind: 'rows', items: items.filter(Boolean), words });
// label is single-line (paths); value may span lines; details are secondary.
// `stacked` puts the value under the label instead of beside it.
export const row = (label, value = '', { status = null, file = null, details = [], strong = false, stacked = false } = {}) => ({
  label,
  value,
  status,
  file,
  details: [details].flat().filter((d) => d !== undefined && d !== null && d !== ''),
  strong,
  stacked
});
export const status = (word, label, value = '', options = {}) => row(label, value, { ...options, status: word });
export const fileRow = (action, path, value = '', options = {}) => row(path, value, { ...options, file: action });
// An overall result line: the outcome word, colored by its status.
export const result = (outcome, detail = '') => ({ kind: 'result', outcome, detail });

// --- formatting -------------------------------------------------------------------

const labelCap = (style) => Math.max(16, Math.min(36, Math.floor(style.width * 0.35)));

function formatRows(block, style, indent) {
  const out = [];
  const hasStatus = block.items.some((item) => item.status);
  const hasFile = block.items.some((item) => item.file);
  const labels = block.items.map((item) => sanitize(item.label, { singleLine: true }));
  const cap = labelCap(style);
  const aligned = labels.filter((l, index) => l.length <= cap && !block.items[index].stacked);
  const labelWidth = Math.min(cap, Math.max(0, ...aligned.map((l) => l.length)));
  block.items.forEach((item, index) => {
    let prefix = '';
    let prefixWidth = 0;
    if (hasStatus) {
      const s = item.status ? statusOf(item.status) : null;
      const cell = s ? (block.words ? `${s.symbol} ${item.status.padEnd(STATUS_WIDTH)}` : s.symbol) : '';
      const width = block.words ? 2 + STATUS_WIDTH + 1 : 1;
      prefix = `${s ? paint(style, [s.tone], cell.trimEnd()) : ''}${' '.repeat(width - cell.trimEnd().length)} `;
      prefixWidth = width + 1;
    }
    if (hasFile) {
      const f = FILE_STATE[item.file] ?? { symbol: '?', word: String(item.file), tone: 'red' };
      const cell = `${f.symbol} ${sanitize(f.word, { singleLine: true }).padEnd(FILE_WIDTH)}`;
      prefix += `${f.tone ? paint(style, [f.tone], cell.trimEnd()) : cell.trimEnd()}${' '.repeat(cell.length - cell.trimEnd().length)} `;
      prefixWidth += cell.length + 1;
    }
    const label = labels[index];
    const value = sanitize(item.value);
    const valueColumn = item.stacked ? indent.length + prefixWidth + 2 : indent.length + prefixWidth + (labelWidth > 0 ? labelWidth + 2 : 0);
    // `strong` marks the important value (or the label of a row without one).
    const valueLines = value === '' ? [] : value.split('\n').map((line) => (item.strong ? paint(style, ['bold'], line) : line));
    const shownLabel = item.strong && valueLines.length === 0 ? paint(style, ['bold'], label) : label;
    if (valueLines.length === 0) {
      out.push(`${indent}${prefix}${shownLabel}`.trimEnd());
    } else if (item.stacked || label.length > labelWidth) {
      // Too long to align: the value goes on its own line, never truncated.
      out.push(`${indent}${prefix}${shownLabel}`.trimEnd());
      valueLines.forEach((line) => out.push(`${' '.repeat(valueColumn)}${line}`));
    } else {
      const pad = label === '' && labelWidth === 0 ? '' : ' '.repeat(labelWidth - label.length + 2);
      out.push(`${indent}${prefix}${shownLabel}${pad}${valueLines[0]}`);
      valueLines.slice(1).forEach((line) => out.push(`${' '.repeat(valueColumn)}${line}`));
    }
    // Secondary text sits under the label of a status/file row, under the value of a plain one.
    const detailIndent = ' '.repeat(hasStatus || hasFile ? indent.length + prefixWidth + 2 : valueColumn);
    for (const detail of item.details) {
      sanitize(detail)
        .split('\n')
        .forEach((line) => out.push(`${detailIndent}${paint(style, ['dim'], line)}`));
    }
  });
  return out;
}

function formatBlock(block, style, indent, out) {
  switch (block.kind) {
    case 'heading':
      out.push(`${indent}${paint(style, ['bold'], sanitize(block.title, { singleLine: true }))}`);
      block.notes.forEach((note) => sanitize(note).split('\n').forEach((line) => out.push(`${indent}${paint(style, ['dim'], line)}`)));
      return;
    case 'section':
      out.push('', `${indent}${paint(style, ['bold', 'cyan'], sanitize(block.title, { singleLine: true }))}`);
      block.body.forEach((child) => formatBlock(child, style, `${indent}  `, out));
      return;
    case 'group':
      block.body.forEach((child) => formatBlock(child, style, `${indent}    `, out));
      return;
    case 'text':
      for (const line of block.lines.flatMap((l) => sanitize(l).split('\n'))) {
        out.push(line === '' ? '' : `${indent}${block.tone ? paint(style, [block.tone], line) : line}`);
      }
      return;
    case 'command':
      block.lines.flatMap((l) => sanitize(l).split('\n')).forEach((line) => out.push(line === '' ? '' : `${indent}  ${paint(style, ['bold'], line)}`));
      return;
    case 'diff':
      // Diff bodies are repository content: sanitized, never re-colored, never
      // indented, so they stay readable as a patch.
      sanitize(String(block.body ?? '').trimEnd()).split('\n').forEach((line) => out.push(line));
      return;
    case 'blank':
      out.push('');
      return;
    case 'rows':
      out.push(...formatRows(block, style, indent));
      return;
    case 'result': {
      const word = OUTCOME[block.outcome] ?? 'FAIL';
      const s = statusOf(word);
      const outcome = sanitize(block.outcome, { singleLine: true });
      const detail = sanitize(block.detail, { singleLine: true });
      out.push(`${indent}${paint(style, [s.tone, 'bold'], `${s.symbol} ${outcome}`)}${detail ? `  ${detail}` : ''}`);
      return;
    }
    default:
      throw new Error(`unknown output block '${block.kind}'`);
  }
}

// blocks -> text, ending in one newline. Leading blank lines are dropped.
export function format(blocks, style = PLAIN) {
  const out = [];
  children([blocks]).forEach((block) => formatBlock(block, style, '', out));
  while (out.length > 0 && out[0] === '') {
    out.shift();
  }
  return `${out.join('\n')}\n`;
}
