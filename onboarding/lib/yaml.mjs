// A strict, dependency-free YAML SUBSET: enough for .ssd/onboarding.yml and for
// structurally checking the workflows ssd-onboard generates, and nothing more.
//
// The toolkit and this CLI import Node builtins only (asserted in CI), so a real
// YAML library is not available. A subset parser is only safe if it REFUSES what
// it does not understand rather than guessing, so:
//
//   supported  block mappings, block sequences, `- key: value` items, plain and
//              single/double-quoted scalars, `|` / `>` block scalars (with
//              `-` / `+` chomping), `[]` / `{}` empty collections, comments
//   refused    anchors, aliases, tags, non-empty flow collections, multiple
//              documents, directives, tabs in indentation, duplicate keys,
//              plain scalars containing ": " or " #"
//
// Scalars: `true` / `false` become booleans and `null` / `~` / empty become null.
// EVERYTHING ELSE IS A STRING. This deliberately differs from YAML's numeric
// resolution: an AWS account ID such as 012345678901 must never become a number
// and lose its leading zero. The serializer quotes anything a YAML 1.1 or 1.2
// reader could resolve to a non-string, so other tools read the same values.

export class YamlSubsetError extends Error {
  constructor(message, line) {
    super(line ? `line ${line}: ${message}` : message);
    this.name = 'YamlSubsetError';
    this.line = line;
  }
}

const RESERVED_PLAIN = /^(?:true|false|null|~|yes|no|on|off|y|n)$/i;
const NUMERIC_LIKE = /^[-+]?(?:\.?[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|0x[0-9a-fA-F_]+|0o?[0-7_]+|\.inf|\.nan)$/i;
// `@` and backtick are reserved indicators and may not START a plain scalar.
const SAFE_PLAIN = /^[A-Za-z0-9_./+-][A-Za-z0-9_./@+$ ()=,-]*$/;

function isBlank(text) {
  return text.trim() === '' || /^\s*#/.test(text);
}

// Strips a trailing comment that begins outside quotes: a `#` at the start of
// the content or preceded by whitespace.
function stripComment(text, lineNo) {
  let quote = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (quote === '"' && char === '\\') {
        index += 1;
      } else if (char === quote) {
        if (quote === "'" && text[index + 1] === "'") {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if ((char === '"' || char === "'") && (index === 0 || /[\s:[{,-]/.test(text[index - 1]))) {
      quote = char;
    } else if (char === '#' && (index === 0 || /\s/.test(text[index - 1]))) {
      return text.slice(0, index).trimEnd();
    }
  }
  if (quote) {
    throw new YamlSubsetError('unterminated quoted scalar', lineNo);
  }
  return text.trimEnd();
}

function parseQuoted(text, lineNo) {
  const quote = text[0];
  let out = '';
  let index = 1;
  for (; index < text.length; index += 1) {
    const char = text[index];
    if (quote === "'") {
      if (char === "'") {
        if (text[index + 1] === "'") {
          out += "'";
          index += 1;
          continue;
        }
        break;
      }
      out += char;
    } else {
      if (char === '\\') {
        const next = text[index + 1];
        const escapes = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', 0: '\0' };
        if (next in escapes) {
          out += escapes[next];
          index += 1;
          continue;
        }
        if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(index + 2, index + 6))) {
          out += String.fromCharCode(Number.parseInt(text.slice(index + 2, index + 6), 16));
          index += 5;
          continue;
        }
        throw new YamlSubsetError(`unsupported escape \\${next}`, lineNo);
      }
      if (char === '"') {
        break;
      }
      out += char;
    }
  }
  if (index >= text.length) {
    throw new YamlSubsetError('unterminated quoted scalar', lineNo);
  }
  const rest = text.slice(index + 1).trim();
  if (rest !== '') {
    throw new YamlSubsetError(`unexpected text after quoted scalar: ${rest}`, lineNo);
  }
  return out;
}

function parseScalar(raw, lineNo) {
  const text = raw.trim();
  if (text === '' || text === 'null' || text === '~') {
    return null;
  }
  if (text === 'true') {
    return true;
  }
  if (text === 'false') {
    return false;
  }
  if (text === '[]') {
    return [];
  }
  if (text === '{}') {
    return {};
  }
  if (text[0] === '"' || text[0] === "'") {
    return parseQuoted(text, lineNo);
  }
  if (/^[&*!%@`]/.test(text)) {
    throw new YamlSubsetError(`anchors, aliases, tags and directives are not supported: ${text}`, lineNo);
  }
  if (text[0] === '[' || text[0] === '{') {
    throw new YamlSubsetError(`flow collections are not supported: ${text}`, lineNo);
  }
  if (/:(\s|$)/.test(text)) {
    throw new YamlSubsetError(`plain scalar contains ": " (quote it): ${text}`, lineNo);
  }
  return text;
}

// Finds the mapping-key separator ": " (or a trailing ":") outside quotes.
function splitKey(text, lineNo) {
  let key;
  let rest;
  if (text[0] === '"' || text[0] === "'") {
    const quote = text[0];
    let index = 1;
    for (; index < text.length; index += 1) {
      if (quote === '"' && text[index] === '\\') {
        index += 1;
      } else if (text[index] === quote) {
        if (quote === "'" && text[index + 1] === "'") {
          index += 1;
        } else {
          break;
        }
      }
    }
    key = parseQuoted(text.slice(0, index + 1), lineNo);
    rest = text.slice(index + 1);
    if (!/^:(\s|$)/.test(rest)) {
      return null;
    }
    return { key, value: rest.slice(1) };
  }
  const match = /^([^\s:#'"&*!|>%@`[\]{},][^:#]*?)\s*:(\s+|$)(.*)$/.exec(text);
  if (!match) {
    return null;
  }
  [, key, , rest] = match;
  return { key, value: rest };
}

function tokenize(source) {
  if (source.includes('\r')) {
    source = source.replace(/\r\n?/g, '\n');
  }
  const lines = source.split('\n');
  return lines.map((raw, index) => {
    const lineNo = index + 1;
    const indentMatch = /^( *)(\t?)/.exec(raw);
    if (indentMatch[2]) {
      throw new YamlSubsetError('tab in indentation', lineNo);
    }
    return { raw, indent: indentMatch[1].length, lineNo };
  });
}

class Parser {
  constructor(source) {
    this.lines = tokenize(source);
    this.pos = 0;
  }

  skipBlank() {
    while (this.pos < this.lines.length && isBlank(this.lines[this.pos].raw)) {
      this.pos += 1;
    }
  }

  peek() {
    this.skipBlank();
    return this.lines[this.pos];
  }

  content(line) {
    return stripComment(line.raw.slice(line.indent), line.lineNo);
  }

  parseDocument() {
    const first = this.peek();
    if (!first) {
      return null;
    }
    const text = this.content(first);
    if (/^(---|\.\.\.|%)/.test(text)) {
      throw new YamlSubsetError('document markers and directives are not supported', first.lineNo);
    }
    if (first.indent !== 0) {
      throw new YamlSubsetError('the document must start at column 0', first.lineNo);
    }
    const value = this.parseBlock(0);
    const trailing = this.peek();
    if (trailing) {
      throw new YamlSubsetError(`unexpected content (bad indentation?): ${trailing.raw.trim()}`, trailing.lineNo);
    }
    return value;
  }

  parseBlock(indent) {
    const line = this.peek();
    const text = this.content(line);
    if (text === '-' || text.startsWith('- ')) {
      return this.parseSequence(line.indent);
    }
    if (splitKey(text, line.lineNo)) {
      return this.parseMapping(line.indent);
    }
    if (line.indent < indent) {
      throw new YamlSubsetError('expected an indented block', line.lineNo);
    }
    this.pos += 1;
    return parseScalar(text, line.lineNo);
  }

  // A value following `key:` / `- ` on the same line, or the block beneath it.
  parseValue(inline, parentIndent, lineNo, allowSameIndentSequence) {
    const trimmed = inline.trim();
    const block = /^([|>])([-+]?)$/.exec(trimmed);
    if (block) {
      return this.parseBlockScalar(parentIndent, block[1], block[2]);
    }
    if (trimmed !== '') {
      return parseScalar(trimmed, lineNo);
    }
    const next = this.peek();
    if (!next) {
      return null;
    }
    const nextText = this.content(next);
    if (next.indent > parentIndent) {
      return this.parseBlock(next.indent);
    }
    if (
      allowSameIndentSequence &&
      next.indent === parentIndent &&
      (nextText === '-' || nextText.startsWith('- '))
    ) {
      return this.parseSequence(parentIndent);
    }
    return null;
  }

  parseMapping(indent) {
    const result = {};
    for (;;) {
      const line = this.peek();
      if (!line || line.indent < indent) {
        break;
      }
      if (line.indent > indent) {
        throw new YamlSubsetError('unexpected indentation', line.lineNo);
      }
      const text = this.content(line);
      if (text === '-' || text.startsWith('- ')) {
        break;
      }
      const pair = splitKey(text, line.lineNo);
      if (!pair) {
        throw new YamlSubsetError(`expected "key: value": ${text}`, line.lineNo);
      }
      if (Object.hasOwn(result, pair.key)) {
        throw new YamlSubsetError(`duplicate key "${pair.key}"`, line.lineNo);
      }
      this.pos += 1;
      result[pair.key] = this.parseValue(pair.value, indent, line.lineNo, true);
    }
    return result;
  }

  parseSequence(indent) {
    const result = [];
    for (;;) {
      const line = this.peek();
      if (!line || line.indent < indent) {
        break;
      }
      const text = this.content(line);
      if (line.indent > indent || !(text === '-' || text.startsWith('- '))) {
        if (line.indent === indent) {
          break;
        }
        throw new YamlSubsetError('unexpected indentation in sequence', line.lineNo);
      }
      const inline = text === '-' ? '' : text.slice(2);
      const leading = inline.length - inline.trimStart().length;
      const itemIndent = indent + 2 + leading;
      const itemText = inline.trimStart();
      if (itemText !== '' && (itemText === '-' || itemText.startsWith('- ') || splitKey(itemText, line.lineNo))) {
        // `- key: value` or `- - x`: re-read this line as a block starting at
        // the item's content column.
        this.lines[this.pos] = {
          raw: `${' '.repeat(itemIndent)}${line.raw.slice(line.indent + 2 + leading)}`,
          indent: itemIndent,
          lineNo: line.lineNo
        };
        result.push(this.parseBlock(itemIndent));
      } else {
        this.pos += 1;
        result.push(this.parseValue(itemText, indent, line.lineNo, false));
      }
    }
    return result;
  }

  parseBlockScalar(parentIndent, style, chomp) {
    const collected = [];
    let contentIndent = null;
    while (this.pos < this.lines.length) {
      const line = this.lines[this.pos];
      if (line.raw.trim() === '') {
        collected.push('');
        this.pos += 1;
        continue;
      }
      if (contentIndent === null) {
        if (line.indent <= parentIndent) {
          break;
        }
        contentIndent = line.indent;
      }
      if (line.indent < contentIndent) {
        break;
      }
      collected.push(line.raw.slice(contentIndent));
      this.pos += 1;
    }
    // Trailing blank lines belong to chomping, not to the next node.
    let trailingBlank = 0;
    while (collected.length > 0 && collected.at(-1) === '') {
      collected.pop();
      trailingBlank += 1;
    }
    let body;
    if (style === '|') {
      body = collected.join('\n');
    } else {
      body = '';
      for (let index = 0; index < collected.length; index += 1) {
        const current = collected[index];
        if (index === 0) {
          body = current;
          continue;
        }
        const previous = collected[index - 1];
        // Each empty line is one line break; the break before it is folded away.
        if (current === '') {
          body += '\n';
        } else if (previous === '') {
          body += current;
        } else if (/^\s/.test(current) || /^\s/.test(previous)) {
          body += '\n' + current;
        } else {
          body += ' ' + current;
        }
      }
    }
    if (collected.length === 0) {
      return '';
    }
    if (chomp === '-') {
      return body;
    }
    if (chomp === '+') {
      return body + '\n'.repeat(trailingBlank + 1);
    }
    return `${body}\n`;
  }
}

export function parseYaml(source) {
  if (typeof source !== 'string') {
    throw new YamlSubsetError('YAML source must be a string');
  }
  return new Parser(source).parseDocument();
}

// --- serialization (the config file only: mappings, sequences, scalars) ------

export function formatScalar(value) {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    throw new YamlSubsetError('numbers are serialized as strings; convert before serializing');
  }
  const text = String(value);
  if (text.includes('\n')) {
    throw new YamlSubsetError('multi-line strings are not supported in the config file');
  }
  if (
    text !== '' &&
    SAFE_PLAIN.test(text) &&
    !RESERVED_PLAIN.test(text) &&
    !NUMERIC_LIKE.test(text) &&
    !/\s$/.test(text) &&
    !/^[-?]\s/.test(text) &&
    text !== '-'
  ) {
    return text;
  }
  return `'${text.replaceAll("'", "''")}'`;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function serializeNode(value, indent, lines) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    for (const item of value) {
      if (isPlainObject(item) && Object.keys(item).length > 0) {
        const nested = [];
        serializeNode(item, indent + 2, nested);
        nested[0] = `${pad}- ${nested[0].slice(indent + 2)}`;
        lines.push(...nested);
      } else if (Array.isArray(item) && item.length > 0) {
        throw new YamlSubsetError('nested sequences are not supported in the config file');
      } else {
        lines.push(`${pad}- ${inlineValue(item)}`);
      }
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const formattedKey = formatScalar(key);
    if ((isPlainObject(child) && Object.keys(child).length > 0) || (Array.isArray(child) && child.length > 0)) {
      lines.push(`${pad}${formattedKey}:`);
      serializeNode(child, Array.isArray(child) ? indent + 2 : indent + 2, lines);
    } else {
      lines.push(`${pad}${formattedKey}: ${inlineValue(child)}`);
    }
  }
}

function inlineValue(value) {
  if (Array.isArray(value)) {
    return '[]';
  }
  if (isPlainObject(value)) {
    return '{}';
  }
  return formatScalar(value);
}

// Serializes a mapping. `comments` maps a top-level key to comment lines emitted
// above it; `header` lines go first. Output is deterministic: key order is the
// object's insertion order, which callers build in schema order.
export function stringifyYaml(value, { header = [], comments = {} } = {}) {
  if (!isPlainObject(value)) {
    throw new YamlSubsetError('the document root must be a mapping');
  }
  const lines = header.map((line) => (line ? `# ${line}` : '#'));
  let first = true;
  for (const [key, child] of Object.entries(value)) {
    if (!first || lines.length > 0) {
      lines.push('');
    }
    first = false;
    for (const comment of comments[key] ?? []) {
      lines.push(comment ? `# ${comment}` : '#');
    }
    serializeNode({ [key]: child }, 0, lines);
  }
  return `${lines.join('\n')}\n`;
}
