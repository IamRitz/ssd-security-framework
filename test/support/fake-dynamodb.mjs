// In-memory DynamoDB for tests. Evaluates the real ConditionExpression and
// UpdateExpression strings the store sends (the subset it uses), and yields to
// the event loop before every operation so concurrent callers genuinely
// interleave: N clicks can all read `pending` before any conditional write lands.
import { setImmediate as yieldTick } from 'node:timers/promises';

function tokenize(expression) {
  return expression.match(/\(|\)|attribute_not_exists\([^)]+\)|attribute_exists\([^)]+\)|<=|>=|=|<|>|[#:\w]+/g);
}

function evaluate(expression, item, names = {}, values = {}) {
  if (!expression) return true;
  const tokens = tokenize(expression);
  let position = 0;
  const attr = (token) => {
    const name = names[token] ?? token;
    const value = item?.[name];
    return value === undefined ? undefined : (value.S ?? value.N);
  };
  const operand = (token) => (token.startsWith(':') ? values[token].S ?? values[token].N : attr(token));

  function primary() {
    const token = tokens[position++];
    if (token === '(') {
      const result = or();
      position++; // ')'
      return result;
    }
    const fn = /^attribute_(not_)?exists\(([^)]+)\)$/.exec(token);
    if (fn) return fn[1] ? attr(fn[2].trim()) === undefined : attr(fn[2].trim()) !== undefined;
    const op = tokens[position++];
    const left = operand(token);
    const right = operand(tokens[position++]);
    if (left === undefined) return false;
    return { '=': left === right, '<': left < right, '>': left > right, '<=': left <= right, '>=': left >= right }[op];
  }
  function and() {
    let result = primary();
    while (tokens[position] === 'AND') {
      position++;
      result = primary() && result;
    }
    return result;
  }
  function or() {
    let result = and();
    while (tokens[position] === 'OR') {
      position++;
      result = and() || result;
    }
    return result;
  }
  return or();
}

function conditionFailed() {
  const error = new Error('The conditional request failed');
  error.name = 'ConditionalCheckFailedException';
  return error;
}

export function createFakeDynamo() {
  const table = new Map();
  const log = [];

  async function call(operation, input) {
    await yieldTick();
    log.push(operation);
    const id = (input.Key ?? input.Item).requestId.S;
    const current = table.get(id);
    const names = input.ExpressionAttributeNames;
    const values = input.ExpressionAttributeValues;

    if (operation === 'GetItem') return { Item: current && globalThis.structuredClone(current) };
    if (!evaluate(input.ConditionExpression, current, names, values)) throw conditionFailed();

    if (operation === 'PutItem') {
      table.set(id, globalThis.structuredClone(input.Item));
    } else if (operation === 'DeleteItem') {
      table.delete(id);
    } else if (operation === 'UpdateItem') {
      const next = globalThis.structuredClone(current ?? { requestId: { S: id } });
      const [setPart, removePart] = input.UpdateExpression.split(/\s+REMOVE\s+/);
      for (const assignment of setPart.replace(/^SET\s+/, '').split(',')) {
        const [name, value] = assignment.split('=').map((part) => part.trim());
        next[names?.[name] ?? name] = globalThis.structuredClone(values[value]);
      }
      for (const name of removePart ? removePart.split(',') : []) delete next[name.trim()];
      table.set(id, next);
    } else {
      throw new Error(`fake DynamoDB does not support ${operation}`);
    }
    return {};
  }

  return { client: { call }, table, log };
}
