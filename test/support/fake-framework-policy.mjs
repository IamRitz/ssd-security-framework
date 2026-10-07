// A fake of SSM GetParameter behind the REAL framework policy
// (broker/identity/framework-policy.mjs), so broker tests exercise the real
// parameter name, parsing and fail-closed states.
//
// The parameter starts as the canonical value admitting `shas` (default: the
// fixture's FRAMEWORK_SHA). `allow(shas)` rewrites it canonically; `set(value)`
// stores any raw value (string, `{ Type, Value }`, or an Error to throw);
// `remove()` deletes it (ParameterNotFound). Every lookup is recorded, with an
// optional shared `events` log for ordering assertions.
import { createFrameworkPolicy, frameworkPolicyParameterName, renderFrameworkPolicy } from '../../broker/identity/framework-policy.mjs';
import { ssmError } from './fake-approvers.mjs';
import { FRAMEWORK_SHA } from './jwt-fixtures.mjs';

export function fakeFrameworkPolicy({ shas = [FRAMEWORK_SHA], environment = 'production', events = null } = {}) {
  const name = frameworkPolicyParameterName(environment);
  let entry = renderFrameworkPolicy(environment, shas);
  const requested = [];
  const getParameter = async (requestedName) => {
    requested.push(requestedName);
    events?.push('policy');
    if (requestedName !== name || entry === undefined) throw ssmError('ParameterNotFound');
    if (entry instanceof Error) throw entry;
    return typeof entry === 'string' ? { Name: requestedName, Type: 'String', Value: entry } : { Name: requestedName, ...entry };
  };
  return {
    name,
    requested,
    policy: createFrameworkPolicy({ getParameter, environment }),
    allow: (next) => {
      entry = renderFrameworkPolicy(environment, next);
    },
    set: (value) => {
      entry = value;
    },
    remove: () => {
      entry = undefined;
    }
  };
}
