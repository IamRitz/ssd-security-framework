// Interactive prompting behind a small interface, so `init` can be driven by a
// terminal or by keyed scripted answers in tests. Every question has a stable
// `id`; the text is for people.
//
// Defaults and `say` text can come from the repository (a remote, Dockerfile
// paths, an existing .semgrepignore), so everything the terminal prompter
// echoes is sanitized first (output.mjs).
import { createInterface } from 'node:readline/promises';

import { sanitize } from './output.mjs';

export function terminalPrompter({ input = process.stdin, output = process.stderr } = {}) {
  const rl = createInterface({ input, output, terminal: Boolean(input.isTTY) });
  return {
    say(text) {
      output.write(`${sanitize(text)}\n`);
    },
    async ask({ question, default: fallback = '', validate }) {
      for (;;) {
        const suffix = fallback !== '' ? ` [${sanitize(fallback, { singleLine: true })}]` : '';
        const answer = (await rl.question(`${sanitize(question)}${suffix}: `)).trim();
        const value = answer === '' ? fallback : answer;
        const problem = validate?.(value);
        if (!problem) {
          return value;
        }
        output.write(`  ${sanitize(problem)}\n`);
      }
    },
    async confirm({ question, default: fallback = false }) {
      for (;;) {
        const answer = (await rl.question(`${sanitize(question)} ${fallback ? '[Y/n]' : '[y/N]'}: `)).trim().toLowerCase();
        if (answer === '') {
          return fallback;
        }
        if (['y', 'yes'].includes(answer)) {
          return true;
        }
        if (['n', 'no'].includes(answer)) {
          return false;
        }
      }
    },
    async choose({ question, choices, default: fallback }) {
      output.write(`${sanitize(question)}\n`);
      const width = Math.max(...choices.map((choice) => sanitize(choice.value, { singleLine: true }).length));
      choices.forEach((choice, index) => {
        const value = sanitize(choice.value, { singleLine: true });
        output.write(`  ${String(index + 1).padStart(String(choices.length).length)}  ${choice.help ? `${value.padEnd(width)}  ${sanitize(choice.help)}` : value}\n`);
      });
      const defaultIndex = choices.findIndex((choice) => choice.value === fallback);
      for (;;) {
        const answer = (await rl.question(`Choice${defaultIndex >= 0 ? ` [${defaultIndex + 1}]` : ''}: `)).trim();
        if (answer === '' && defaultIndex >= 0) {
          return choices[defaultIndex].value;
        }
        const chosen = choices[Number(answer) - 1] ?? choices.find((choice) => choice.value === answer);
        if (chosen) {
          return chosen.value;
        }
      }
    },
    close() {
      rl.close();
    }
  };
}

// answers: { [id]: value }. A missing id takes the default. Every question asked
// is recorded in `asked`, so tests can assert what was — and was not — asked.
export function scriptedPrompter(answers = {}) {
  const asked = [];
  const said = [];
  const take = (id) => {
    asked.push(id);
    return Object.hasOwn(answers, id) ? answers[id] : undefined;
  };
  return {
    asked,
    said,
    say(text) {
      said.push(text);
    },
    async ask({ id, question, default: fallback = '', validate }) {
      const answer = take(id);
      const value = answer === undefined ? fallback : String(answer);
      const problem = validate?.(value);
      if (problem) {
        throw new Error(`scripted answer '${value}' rejected for ${id} ("${question}"): ${problem}`);
      }
      return value;
    },
    async confirm({ id, default: fallback = false }) {
      const answer = take(id);
      return answer === undefined ? fallback : answer === true;
    },
    async choose({ id, question, choices, default: fallback }) {
      const answer = take(id);
      const value = answer === undefined ? fallback : answer;
      if (!choices.some((choice) => choice.value === value)) {
        throw new Error(`scripted choice '${value}' is not offered for ${id} ("${question}")`);
      }
      return value;
    },
    close() {}
  };
}
