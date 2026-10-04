// A fake of SSM GetParameter behind the REAL approver source
// (broker/authorize/approvers.mjs), so broker tests exercise the real parameter
// naming, parsing and fail-closed states.
//
// `parameters` maps a parameter NAME to either a String value, a full
// `{ Type, Value }` parameter, or an Error to throw. A name not in the map
// throws ParameterNotFound, as SSM does. Every requested name is recorded.
import { approverParameterName, createApproverSource } from '../../broker/authorize/approvers.mjs';

export const SLACK_A = 'UAPPROVERA1';
export const SLACK_B = 'UAPPROVERB1';

export const approverParameter = (repositoryId, environment = 'production') =>
  approverParameterName(environment, repositoryId);

export function ssmError(name) {
  const error = new Error(`${name} (fake)`);
  error.name = name;
  return error;
}

export function fakeApproverSource(parameters = {}, { environment = 'production' } = {}) {
  const requested = [];
  const getParameter = async (name) => {
    requested.push(name);
    if (!Object.hasOwn(parameters, name)) throw ssmError('ParameterNotFound');
    const entry = parameters[name];
    if (entry instanceof Error) throw entry;
    return typeof entry === 'string' ? { Name: name, Type: 'String', Value: entry } : { Name: name, ...entry };
  };
  return { requested, parameters, source: createApproverSource({ getParameter, environment }) };
}

// The common case: repository_id -> list of Slack user IDs.
export const approversById = (byId, options) =>
  fakeApproverSource(
    Object.fromEntries(Object.entries(byId).map(([id, users]) => [approverParameter(id), JSON.stringify(users)])),
    options
  );
