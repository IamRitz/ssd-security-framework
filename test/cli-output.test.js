// The human output layer (onboarding/lib/output.mjs): color only on an
// interactive terminal, status words that never depend on color, no truncation,
// and repository-controlled text that can never drive the terminal. --json and
// exit codes are untouched by any of it.
import assert from 'node:assert/strict';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, it } from 'node:test';

import { main } from '../onboarding/cli.mjs';
import { doctorBlocks } from '../onboarding/lib/doctor.mjs';
import {
  FILE_STATE,
  PLAIN,
  STATUS,
  fileRow,
  format,
  heading,
  outputStyle,
  row,
  rows,
  sanitize,
  section,
  status,
  text
} from '../onboarding/lib/output.mjs';
import { terminalPrompter } from '../onboarding/lib/prompt.mjs';
import { reportBlocks } from '../onboarding/lib/report.mjs';
import { serializeConfig } from '../onboarding/lib/config.mjs';
import { FRAMEWORK, capture, config, makeRepo, rawConfig, write } from './support/onboarding-fixtures.mjs';

const ESC = '\x1b';
const BEL = '\x07';
// The OSC 8 hyperlink attack: renders "click-me" as a link to evil.example.
const OSC8 = `${ESC}]8;;https://evil.example${BEL}click-me${ESC}]8;;${BEL}`;
const OSC8_VISIBLE = '\\x1b]8;;https://evil.example\\x07click-me\\x1b]8;;\\x07';
const RLO = String.fromCodePoint(0x202e);
const COLOR = { color: true, width: 100 };
const SGR_ONLY = /\x1b\[\d+m/g;
// Any byte a terminal acts on: C0 (except TAB/LF), DEL, C1.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/;

async function cli(root, args, io = {}) {
  const c = capture();
  const code = await main([...args, '--repo', root], { framework: FRAMEWORK, ...c.io, ...io });
  return { code, out: c.text(), err: c.errors() };
}

describe('color detection', () => {
  it('an interactive terminal gets color and its width', () => {
    assert.deepEqual(outputStyle({ isTTY: true, columns: 132 }, {}), { color: true, width: 132 });
    assert.match(format(rows([status('PASS', 'x')]), outputStyle({ isTTY: true }, {})), SGR_ONLY);
  });

  it('a redirected / non-TTY stream is plain, at a fixed width', () => {
    for (const stream of [{ isTTY: false, columns: 50 }, {}, null, undefined]) {
      assert.deepEqual(outputStyle(stream, {}), PLAIN);
    }
  });

  it('NO_COLOR (set, non-empty) and TERM=dumb disable color on a terminal', () => {
    const tty = { isTTY: true, columns: 80 };
    assert.equal(outputStyle(tty, { NO_COLOR: '1' }).color, false);
    assert.equal(outputStyle(tty, { NO_COLOR: 'false' }).color, false, 'any non-empty value');
    assert.equal(outputStyle(tty, { TERM: 'dumb' }).color, false);
    assert.equal(outputStyle(tty, { NO_COLOR: '' }).color, true, 'empty NO_COLOR is unset (no-color.org)');
  });

  it('FORCE_COLOR is not read: color comes only from the stream', () => {
    assert.equal(outputStyle({ isTTY: false }, { FORCE_COLOR: '3' }).color, false);
  });

  it('injected writers (tests, embedding) are plain unless io.color', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    assert.doesNotMatch((await cli(root, ['inspect'])).out, /\x1b/);
    assert.match((await cli(root, ['inspect'], { color: true })).out, SGR_ONLY);
  });
});

describe('status vocabulary', () => {
  const all = rows(['PASS', 'WARN', 'FAIL', 'NOT VERIFIED'].map((word) => status(word, `check ${word}`)), { words: true });

  it('symbol and word appear together, with or without color', () => {
    for (const style of [PLAIN, COLOR]) {
      const out = format(all, style).replace(SGR_ONLY, '');
      assert.match(out, /^✓ PASS +check PASS$/m);
      assert.match(out, /^! WARN +check WARN$/m);
      assert.match(out, /^✗ FAIL +check FAIL$/m);
      assert.match(out, /^\? NOT VERIFIED +check NOT VERIFIED$/m);
    }
  });

  it('FAIL is red and never takes the PASS symbol or color; PASS is the only green', () => {
    assert.equal(STATUS.FAIL.symbol, '✗');
    assert.equal(STATUS.FAIL.tone, 'red');
    assert.notEqual(STATUS.FAIL.symbol, STATUS.PASS.symbol);
    assert.deepEqual(Object.keys(STATUS).filter((word) => STATUS[word].tone === 'green'), ['PASS']);
    const fail = format(rows([status('FAIL', 'x')]), COLOR);
    assert.match(fail, /\x1b\[31m✗\x1b\[39m/);
    assert.doesNotMatch(fail, /✓|\x1b\[32m/);
  });

  it('an unknown status never looks like a pass', () => {
    const out = format(rows([status('SOMETHING', 'x')], { words: true }), COLOR);
    assert.doesNotMatch(out, /✓|\x1b\[32m/);
    assert.match(out, /SOMETHING/);
  });

  it('every file state has its own symbol and word; a conflict is red', () => {
    const out = format(rows(Object.keys(FILE_STATE).map((action) => fileRow(action, `${action}.yml`))));
    assert.match(out, /^\+ create +create\.yml$/m);
    assert.match(out, /^~ update +update\.yml$/m);
    assert.match(out, /^= unchanged +unchanged\.yml$/m);
    assert.match(out, /^! conflict +conflict\.yml$/m);
    assert.match(out, /^! overwrite +forced\.yml$/m);
    assert.match(out, /^~ adopt +adopted\.yml$/m);
    assert.match(out, /^- stale +stale\.yml$/m);
    assert.equal(FILE_STATE.conflict.tone, 'red');
  });
});

describe('terminal-control sanitization', () => {
  it('OSC 8 hyperlinks, CR rewrites, CSI, C1 and bidi overrides are rendered visibly', () => {
    assert.equal(sanitize(OSC8), OSC8_VISIBLE);
    assert.equal(sanitize('foo\rPASS something'), 'foo\\rPASS something');
    assert.equal(sanitize(`${ESC}[31mred`), '\\x1b[31mred');
    assert.equal(sanitize(`${ESC}]0;owned${BEL}`), '\\x1b]0;owned\\x07', 'terminal title');
    assert.equal(sanitize('a\x9b31mb'), `a\\u009b31mb`, 'C1 CSI');
    assert.equal(sanitize(`x${RLO}y`), `x\\u202ey`);
    assert.equal(sanitize('tab\tand\nnewline'), 'tab\tand\nnewline', 'TAB and LF are not controls');
    assert.equal(sanitize('a\nb', { singleLine: true }), 'a\\nb');
  });

  it('text is preserved exactly apart from the escapes', () => {
    const path = 'services/payments/src/main/resources/app.config — ünïcode ✓ [brackets] `ticks` 068303774554f189b7444a0d3c95c6aeb7798608';
    assert.equal(sanitize(path), path);
  });

  it('every block kind sanitizes before it styles', () => {
    const blocks = [
      heading(OSC8, `note ${OSC8}`),
      section(`section ${OSC8}`, rows([row(OSC8, OSC8, { details: OSC8 }), status('FAIL', OSC8, OSC8), fileRow('create', OSC8)]), text(OSC8)),
      rows([row('foo\rPASS something', 'foo\rPASS something')])
    ];
    for (const style of [PLAIN, COLOR]) {
      const out = format(blocks, style);
      assert.doesNotMatch(out.replace(SGR_ONLY, ''), CONTROL, 'only the formatter’s own SGR codes reach the terminal');
      assert.ok(out.includes(OSC8_VISIBLE));
      assert.ok(out.includes('foo\\rPASS something'));
    }
  });

  it('a newline in a label cannot fake a row of its own', () => {
    const out = format(rows([fileRow('create', 'a.yml\n✓ PASS  everything')]));
    assert.equal(out, '+ create     a.yml\\n✓ PASS  everything\n');
  });

  // The attack shape through the real CLI: a repository name and a workflow
  // path carrying an OSC 8 hyperlink. (A CR cannot reach these paths: the
  // config parser rejects it. The inspect test below carries one in a file name.)
  it('validate: an OSC 8 repository name is shown escaped on stdout, never as a link', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    write(root, '.ssd/onboarding.yml', serializeConfig(rawConfig('source-only', { repository: { slug: `acme/${OSC8}` } })));
    for (const io of [{}, { color: true }]) {
      const result = await cli(root, ['validate'], io);
      assert.equal(result.code, 1);
      assert.doesNotMatch(`${result.out}${result.err}`.replace(SGR_ONLY, ''), CONTROL, 'no active ESC or BEL');
      assert.ok(result.out.includes(`'acme/${OSC8_VISIBLE}' is not valid`), 'the repository name is visible, escaped');
    }
  });

  it('init: an OSC 8 workflow path is shown escaped on stderr, never as a link', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    const from = join(root, '..', `${root.split('/').pop()}-partial.json`);
    writeFileSync(from, JSON.stringify({ profile: 'source-only', framework: { ref: FRAMEWORK.sha }, workflows: { security: `.github/workflows/${OSC8}.yml` } }));
    t.after(() => rmSync(from, { force: true }));
    const result = await cli(root, ['init', '--non-interactive', '--from', from], { color: true });
    assert.equal(result.code, 1);
    assert.doesNotMatch(`${result.out}${result.err}`.replace(SGR_ONLY, ''), CONTROL);
    assert.ok(result.err.includes(`workflows.security: '.github/workflows/${OSC8_VISIBLE}.yml' is not valid`), result.err);
  });

  it('inspect: repository file names with control characters are shown escaped', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n', [`svc${ESC}[2Jx/requirements.txt`]: 'flask==3.0.0\n', '.github/workflows/cr\rPASS.yml': 'name: y\n' });
    const { code, out } = await cli(root, ['inspect'], { color: true });
    assert.equal(code, 0);
    assert.doesNotMatch(out.replace(SGR_ONLY, ''), CONTROL);
    assert.ok(out.includes('svc\\x1b[2Jx/requirements.txt'));
    assert.ok(out.includes('.github/workflows/cr\\rPASS.yml'));
  });

  it('stderr is sanitized too (errors echo arguments and paths)', async (t) => {
    const root = makeRepo(t, {});
    const result = await cli(root, [`bogus${OSC8}`]);
    assert.equal(result.code, 2);
    assert.doesNotMatch(result.err, CONTROL);
    assert.ok(result.err.includes(`unknown command 'bogus${OSC8_VISIBLE}'`));
  });

  it('the terminal prompter sanitizes what it echoes; answers are returned unchanged', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let echoed = '';
    output.on('data', (chunk) => {
      echoed += chunk;
    });
    const prompter = terminalPrompter({ input, output });
    prompter.say(`Dockerfiles found: ${OSC8}`);
    const choice = prompter.choose({ id: 'profile', question: 'Profile', choices: [{ value: 'source-only', help: `help ${OSC8}` }, { value: 'container-self-managed' }] });
    input.write('2\n');
    assert.equal(await choice, 'container-self-managed');
    const asked = prompter.ask({ id: 'slug', question: 'GitHub repository', default: `acme/${OSC8}` });
    input.write('\n');
    assert.equal(await asked, `acme/${OSC8}`, 'the value is data; only its display is escaped');
    prompter.close();
    assert.doesNotMatch(echoed, CONTROL);
    assert.ok(echoed.includes(`Dockerfiles found: ${OSC8_VISIBLE}`));
    assert.match(echoed, /^ {2}1 {2}source-only {13}help /m);
    assert.match(echoed, /^ {2}2 {2}container-self-managed$/m);
    assert.ok(echoed.includes(`[acme/${OSC8_VISIBLE}]`));
  });
});

describe('layout', () => {
  it('long paths, SHAs and messages are never truncated, whatever the width', () => {
    const path = `${'deeply/nested/'.repeat(20)}package-lock.json`;
    const sha = '068303774554f189b7444a0d3c95c6aeb7798608';
    for (const width of [20, 80, 200]) {
      const out = format(rows([status('FAIL', path, `framework@${sha}`), row('Framework', `IamRitz/ssd-security-framework@${sha}`)]), { color: false, width });
      assert.ok(out.includes(path));
      assert.ok(out.includes(`framework@${sha}`));
      assert.ok(out.includes(`IamRitz/ssd-security-framework@${sha}`));
    }
  });

  it('a label too long to align puts its value on the next line instead', () => {
    const long = 'x'.repeat(60);
    assert.equal(format(rows([row('short', 'a'), row(long, 'b')])), `short  a\n${long}\n       b\n`);
  });

  it('blocking issues are grouped by area, as FAIL, separately from warnings', () => {
    const result = {
      config: config('source-only'),
      rollout: { name: 'onboarding' },
      coverage: {},
      plan: [],
      stale: [],
      warnings: [{ area: 'config', message: 'log-only' }],
      errors: [
        { area: 'dependencies', message: 'frontend/package-lock.json: native npm coverage is missing' },
        { area: 'dependencies', message: 'services/py/requirements.txt: OSV-Scanner only' },
        { area: 'repository', message: 'slug mismatch' }
      ]
    };
    const out = format(reportBlocks(result, { title: 'SSD Validate' }));
    const blocking = out.slice(out.indexOf('Blocking issues (3)'), out.indexOf('\nResult\n'));
    assert.match(blocking, /^ {2}✗ dependencies\n {6}- frontend\/package-lock\.json: native npm coverage is missing\n {6}- services\/py\/requirements\.txt: OSV-Scanner only$/m);
    assert.match(blocking, /^ {2}✗ repository\n {6}slug mismatch$/m);
    assert.doesNotMatch(blocking, /^ {2}! /m, 'a blocking issue is never rendered as a warning');
    assert.match(out, /^Warnings \(1\)\n {2}! config\n {6}log-only$/m);
    assert.match(out, /^Result\n {2}✗ BLOCKED {2}3 blocking issues — generation is blocked$/m);
  });

  it('report result: READY / READY WITH WARNINGS / BLOCKED, and drift blocks validate', () => {
    const base = { config: config('source-only'), rollout: { name: 'onboarding' }, coverage: {}, plan: [], stale: [], warnings: [], errors: [] };
    const outcome = (result, options) => /^Result\n {2}. (.+?) {2}/m.exec(format(reportBlocks(result, options)))[1];
    assert.equal(outcome(base), 'READY');
    assert.equal(outcome({ ...base, warnings: [{ area: 'x', message: 'y' }] }), 'READY WITH WARNINGS');
    assert.equal(outcome({ ...base, errors: [{ area: 'x', message: 'y' }] }), 'BLOCKED');
    assert.equal(outcome(base, { drift: true }), 'BLOCKED');
  });

  it('doctor: the outcome is the machine outcome verbatim; details only for non-PASS checks', () => {
    const check = (id, title, status) => ({ id, title, status, observed: [`${id} observed`], expected: [], why: `${id} why`, remediation: [`${id} how`], evidence: [] });
    for (const [outcome, symbol] of [['READY (LOCAL CHECKS)', '✓'], ['READY WITH WARNINGS', '!'], ['NOT READY', '✗']]) {
      const report = {
        profile: 'source-only',
        repository: 'acme/app',
        outcome,
        counts: { PASS: 1, WARN: 1, FAIL: 0, 'NOT VERIFIED': 1 },
        checks: [check('a', 'Alpha', 'PASS'), check('b', 'Beta', 'WARN'), check('c', 'Gamma', 'NOT VERIFIED')]
      };
      const out = format(doctorBlocks(report));
      assert.ok(out.includes(`  ${symbol} ${outcome}  0 FAIL · 1 WARN · 1 NOT VERIFIED · 1 PASS`), outcome);
      const details = out.slice(out.indexOf('\nDetails\n'), out.indexOf('\nResult\n'));
      assert.doesNotMatch(details, /Alpha/);
      assert.match(details, /^ {2}! WARN {10}Beta\n {6}What +b observed\n {6}Why +b why\n {6}How +b how$/m);
      assert.match(details, /^ {2}\? NOT VERIFIED {2}Gamma$/m);
    }
  });

  it('inspect (no config): context, languages, SAST, containers, dependencies, workflows, governance, next — in that order', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n', 'package.json': '{"dependencies":{"a":"1"}}\n', 'package-lock.json': '{"lockfileVersion":3,"packages":{}}\n' });
    const { out } = await cli(root, ['inspect']);
    const order = ['SSD Inspect', 'Repository', 'Languages', 'SAST', 'Containers', 'Dependencies', 'Workflows', 'Governance', 'Next'].map((title) => out.search(new RegExp(`^${title}$`, 'm')));
    assert.ok(order.every((index, i) => index >= 0 && (i === 0 || index > order[i - 1])), JSON.stringify(order));
    assert.match(out, /^ {2}✓ package-lock\.json +native\+osv\n {6}\S/m, 'row, then its reason beneath');
    assert.match(out, /^ {2}! CODEOWNERS +none$/m);
  });

  it('onboard plan: context, coverage, rollout, security model, files, problems, result — in that order', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    const from = join(root, '..', `${root.split('/').pop()}-partial.json`);
    writeFileSync(from, JSON.stringify({ profile: 'source-only', framework: { ref: FRAMEWORK.sha } }));
    t.after(() => rmSync(from, { force: true }));
    const { code, out } = await cli(root, ['onboard', '--non-interactive', '--from', from]);
    assert.equal(code, 0, out);
    const plan = out.slice(0, out.indexOf('\nReadiness\n'));
    const order = ['Onboarding plan', 'Repository', 'Coverage', 'Rollout', 'Security model', 'Files', 'Warnings \\(\\d+\\)', 'Result'].map((title) => plan.search(new RegExp(`^${title}$`, 'm')));
    assert.ok(order.every((index, i) => index >= 0 && (i === 0 || index > order[i - 1])), JSON.stringify(order));
    assert.match(out, /^Next\n {2}1\. Review the changes:\n {8}git status && git diff$/m, 'commands stand on their own line, unwrapped');
  });

  it('baseline status: the lifecycle with the current state marked, and the next step', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only')));
    const { code, out } = await cli(root, ['baseline', 'status']);
    assert.equal(code, 0);
    assert.match(out, /^ {2}State +onboarding$/m);
    assert.match(out, /^ {2}Lifecycle +\[onboarding\] → candidate-downloaded → baseline-accepted → enforcing$/m);
    assert.match(out, /^Next\n {2}dispatch the bootstrap run/m);
  });
});

describe('machine output and exit codes are untouched', () => {
  it('--json output is identical with and without color, parses, and holds no ANSI or decoration', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n', [`svc${ESC}[31m/requirements.txt`]: 'flask==3.0.0\n' });
    const noConfig = await cli(root, ['inspect', '--json']);
    const plainDoctor = await cli(root, ['doctor', '--json']);
    write(root, '.ssd/onboarding.yml', serializeConfig(rawConfig('source-only', { repository: { slug: `acme/${OSC8}` } })));
    for (const args of [['inspect', '--json'], ['validate', '--json'], ['doctor', '--json']]) {
      const plain = await cli(root, args);
      const colored = await cli(root, args, { color: true });
      assert.equal(colored.out, plain.out, `${args.join(' ')}: byte-identical`);
      assert.equal(colored.code, plain.code);
      assert.equal(plain.err, '', 'nothing on stderr');
      assert.doesNotMatch(plain.out, /\x1b|\\x1b|^SSD |✓|✗/m, 'no ANSI, no human escapes, no headings or symbols');
      assert.equal(plain.out, `${JSON.stringify(JSON.parse(plain.out), null, 2)}\n`, 'exactly JSON.stringify(…, null, 2) and a newline');
    }
    // JSON keeps repository values as data: escaped by JSON itself, not by the human renderer.
    assert.ok(JSON.parse(noConfig.out).manifests.some((m) => m.path === `svc${ESC}[31m/requirements.txt`));
    assert.equal(JSON.parse(plainDoctor.out).outcome, 'ERROR');
    assert.equal(plainDoctor.code, 1);
  });

  it('exit codes by outcome', async (t) => {
    const root = makeRepo(t, { 'src/app.py': 'x = 1\n' });
    assert.equal((await cli(root, ['inspect'])).code, 0);
    assert.equal((await cli(root, ['doctor'])).code, 1, 'no config: runtime error');
    assert.equal((await cli(root, ['validate', '--bogus'])).code, 2, 'usage error');
    assert.equal((await cli(root, ['aws', 'apply'])).code, 2, 'not implemented');
    assert.equal((await cli(root, ['aws', 'plan'])).code, 1, 'no config: configuration error, AWS not contacted');
    assert.equal((await cli(root, ['aws', 'doctor'])).code, 1, 'no config: configuration error, AWS not contacted');
    write(root, '.ssd/onboarding.yml', serializeConfig(config('source-only')));
    assert.equal((await cli(root, ['render', '--check'])).code, 1, 'drift: nothing rendered yet');
    assert.equal((await cli(root, ['render'])).code, 0);
    assert.equal((await cli(root, ['render', '--check'])).code, 0);
    assert.equal((await cli(root, ['baseline', 'status'])).code, 0);
    assert.equal((await cli(root, ['promote', '--enforce', '--yes'])).code, 1, 'no accepted baseline');
  });
});
