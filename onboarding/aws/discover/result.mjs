// Discovery results share one shape, so "absent" can only ever mean AWS said
// the resource does not exist:
//
//   { state: 'present', value }      the call succeeded
//   { state: 'absent', code }        AWS answered with an EXPECTED not-found code
//   { state: 'unverified', error }   anything else: access denied, throttling,
//                                    malformed output, timeout, …
//
// An AccessDenied is never absence: only the not-found codes a caller names
// for that specific call produce `absent`.
import { AwsCliError } from '../aws-cli.mjs';

export const present = (value) => ({ state: 'present', value });
export const absent = (code) => ({ state: 'absent', code });
export const unverified = (error) => ({
  state: 'unverified',
  error: { kind: error?.kind ?? 'runtime', code: error?.code ?? null, operation: error?.operation ?? null, message: error?.message ?? String(error) }
});

// Run one read. `notFound` lists the AWS error codes that mean absence here.
export async function read(aws, argv, { notFound = [] } = {}) {
  try {
    return present(await aws(argv));
  } catch (error) {
    if (!(error instanceof AwsCliError)) {
      throw error;
    }
    // Authentication failures and a missing CLI end the whole run.
    if (error.kind === 'authentication' || error.kind === 'command-unavailable' || error.kind === 'refused') {
      throw error;
    }
    if (error.kind === 'not-found' && notFound.includes(error.code)) {
      return absent(error.code);
    }
    return unverified(error);
  }
}

export const describeError = (result) => {
  const e = result.error;
  const what = { authorization: 'access denied', 'malformed-json': 'malformed AWS output', timeout: 'timed out', 'output-too-large': 'output too large', 'not-found': 'unexpected not-found' }[e.kind] ?? 'AWS error';
  return `${what}${e.operation ? ` calling ${e.operation}` : ''}${e.code ? ` (${e.code})` : ''}${e.message && e.kind !== 'timeout' ? `: ${e.message}` : ''}`;
};
