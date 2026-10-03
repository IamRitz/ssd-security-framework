// Reading the Slack webhook for `github apply` — the ONLY place a secret value
// enters ssd-onboard.
//
// DATAFLOW: terminal (hidden, raw mode, no echo) or a deliberately non-TTY
// stdin  ->  one Buffer  ->  the stdin of `gh secret set` (gh-cli.mjs, the
// single-use secret writer)  ->  zero-filled. It is never placed in argv, the
// environment, a file, a log line, the JSON report or an error message;
// validation errors describe the problem, never the input.

export class SecretInputError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'SecretInputError';
    this.kind = kind;
  }
}

export const MAX_SECRET_BYTES = 4096;

// An incoming-webhook URL: printable ASCII only, https, Slack's hosts.
const WEBHOOK = /^https:\/\/hooks\.slack(?:-gov)?\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]{8,}$/;

// Throws SecretInputError without quoting the value.
export function validateWebhook(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    throw new SecretInputError('empty', 'no webhook URL was provided');
  }
  if (bytes.length > MAX_SECRET_BYTES) {
    throw new SecretInputError('too-long', `the value is longer than ${MAX_SECRET_BYTES} bytes`);
  }
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e) {
      throw new SecretInputError('invalid', 'the value contains whitespace, control or non-ASCII characters; paste only the webhook URL');
    }
  }
  if (!WEBHOOK.test(bytes.toString('latin1'))) {
    throw new SecretInputError('invalid', 'the value is not a Slack incoming-webhook URL (https://hooks.slack.com/services/…)');
  }
}

// One trailing LF or CRLF is the line terminator of piped input, not data.
function stripLineEnd(bytes) {
  let end = bytes.length;
  if (end > 0 && bytes[end - 1] === 0x0a) end -= 1;
  if (end > 0 && bytes[end - 1] === 0x0d) end -= 1;
  return bytes.subarray(0, end);
}

// All of a non-TTY stdin, bounded.
function readPiped(input) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const onData = (chunk) => {
      size += chunk.length;
      if (size > MAX_SECRET_BYTES + 2) {
        cleanup();
        chunks.forEach((c) => c.fill(0));
        reject(new SecretInputError('too-long', `the value is longer than ${MAX_SECRET_BYTES} bytes`));
        return;
      }
      chunks.push(Buffer.from(chunk));
    };
    const onEnd = () => {
      cleanup();
      const all = Buffer.concat(chunks);
      chunks.forEach((c) => c.fill(0));
      const value = Buffer.from(stripLineEnd(all));
      all.fill(0);
      resolve(value);
    };
    const onError = () => {
      cleanup();
      reject(new SecretInputError('read-failed', 'standard input could not be read'));
    };
    const cleanup = () => {
      input.off('data', onData);
      input.off('end', onEnd);
      input.off('error', onError);
    };
    input.on('data', onData);
    input.on('end', onEnd);
    input.on('error', onError);
    input.resume();
  });
}

// A hidden line from a terminal: raw mode, nothing echoed. Enter ends it,
// Backspace edits, Ctrl-C / Ctrl-D abort.
function readHidden(input, output, prompt) {
  return new Promise((resolve, reject) => {
    const buffer = Buffer.alloc(MAX_SECRET_BYTES + 1);
    let length = 0;
    const finish = (error) => {
      input.off('data', onData);
      input.setRawMode(false);
      input.pause();
      output.write('\n');
      if (error) {
        buffer.fill(0);
        reject(error);
        return;
      }
      const value = Buffer.from(buffer.subarray(0, length));
      buffer.fill(0);
      resolve(value);
    };
    const onData = (chunk) => {
      for (const byte of chunk) {
        if (byte === 0x0d || byte === 0x0a) {
          finish(null);
          return;
        }
        if (byte === 0x03) {
          finish(new SecretInputError('aborted', 'aborted: no secret was read'));
          return;
        }
        if (byte === 0x04 && length === 0) {
          finish(new SecretInputError('aborted', 'aborted: no secret was read'));
          return;
        }
        if (byte === 0x7f || byte === 0x08) {
          length = Math.max(0, length - 1);
          continue;
        }
        if (length > MAX_SECRET_BYTES) {
          finish(new SecretInputError('too-long', `the value is longer than ${MAX_SECRET_BYTES} bytes`));
          return;
        }
        buffer[length] = byte;
        length += 1;
      }
    };
    output.write(prompt);
    input.setRawMode(true);
    input.on('data', onData);
    input.resume();
  });
}

// -> Buffer, validated. The caller owns it and zero-fills it after use.
export async function readSecret({ input = process.stdin, output = process.stderr, prompt = 'Webhook URL (input hidden): ' } = {}) {
  let value;
  if (input.isTTY) {
    if (typeof input.setRawMode !== 'function') {
      throw new SecretInputError('no-hidden-input', 'this terminal cannot read input without echoing it; pipe the value on standard input instead');
    }
    value = await readHidden(input, output, prompt);
  } else {
    value = await readPiped(input);
  }
  try {
    validateWebhook(value);
  } catch (error) {
    value.fill(0);
    throw error;
  }
  return value;
}
