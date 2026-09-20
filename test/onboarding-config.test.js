// ssd-onboard: the strict YAML subset and the closed, non-secret config schema.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, it } from 'node:test';

import { findSecretValues, parseConfig, serializeConfig, validateConfig } from '../onboarding/lib/config.mjs';
import { YamlSubsetError, parseYaml, stringifyYaml } from '../onboarding/lib/yaml.mjs';
import { DEPLOY_ROLE, PUSH_ROLE, REF, config, rawConfig } from './support/onboarding-fixtures.mjs';

const errorPaths = (result) => result.errors.map((e) => e.path);
const errorsAt = (result, path) => result.errors.filter((e) => e.path === path).map((e) => e.message).join(' | ');

describe('the YAML subset', () => {
  it('parses every framework workflow and example without error', () => {
    const files = [
      ...readdirSync('.github/workflows').map((f) => `.github/workflows/${f}`),
      ...readdirSync('examples', { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .flatMap((e) => readdirSync(`examples/${e.name}`).filter((f) => f.endsWith('.yml')).map((f) => `examples/${e.name}/${f}`))
    ];
    for (const file of files) {
      const doc = parseYaml(readFileSync(file, 'utf8'));
      assert.ok(doc.jobs && typeof doc.jobs === 'object', `${file} has jobs`);
    }
  });

  it('keeps every non-boolean scalar a string — an account ID never loses its leading zero', () => {
    const doc = parseYaml('a: 012345678901\nb: 3000\nc: true\nd: null\ne: 1.0\nf: on\n');
    assert.deepEqual(doc, { a: '012345678901', b: '3000', c: true, d: null, e: '1.0', f: 'on' });
  });

  it('quotes anything another YAML reader could resolve to a non-string', () => {
    const values = { a: '012345678901', b: 'true', c: 'on', d: '1e3', e: '', f: 'plain', g: '- x', h: "it's", i: '@acme/security', j: 'a: b', k: '#x' };
    const text = stringifyYaml(values);
    const doc = parseYaml(text);
    assert.deepEqual(doc, values);
    assert.match(text, /a: '012345678901'/);
    assert.match(text, /c: 'on'/);
  });

  it('parses block scalars with every chomping mode', () => {
    const doc = parseYaml('a: |\n  x\n  y\n\nb: |-\n  x\nc: >-\n  one\n  two\n\n  three\nd: |+\n  k\n\ne: z\n');
    assert.deepEqual(doc, { a: 'x\ny\n', b: 'x', c: 'one two\nthree', d: 'k\n\n', e: 'z' });
  });

  for (const [label, source] of [
    ['an anchor', 'a: &x 1\n'],
    ['an alias', 'a: *x\n'],
    ['a tag', 'a: !!str 1\n'],
    ['a flow sequence', 'a: [1, 2]\n'],
    ['a flow mapping', 'a: {b: 1}\n'],
    ['a second document', '---\na: 1\n'],
    ['a duplicate key', 'a: 1\na: 2\n'],
    ['a tab in indentation', 'a:\n\tb: 1\n'],
    ['an unquoted ": " in a value', 'a: b: c\n'],
    ['an unterminated quote', "a: 'b\n"]
  ]) {
    it(`refuses ${label} rather than guessing`, () => {
      assert.throws(() => parseYaml(source), YamlSubsetError);
    });
  }
});

describe('the config schema is closed', () => {
  it('accepts every fixture profile', () => {
    for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
      assert.deepEqual(validateConfig(rawConfig(profile)).errors, [], profile);
    }
  });

  it('rejects an unknown key (a typo must not silently leave the repo in log-only)', () => {
    const result = validateConfig(rawConfig('source-only', { rollout: { gateMod: 'enforce' } }));
    assert.ok(errorPaths(result).includes('rollout.gateMod'));
  });

  it('refuses an unknown schema version', () => {
    assert.ok(errorPaths(validateConfig(rawConfig('source-only', { schemaVersion: '2' }))).includes('schemaVersion'));
  });

  it('refuses a delivery section on a non-ECR profile and a container section on source-only', () => {
    const r1 = validateConfig({ ...rawConfig('container-self-managed'), delivery: rawConfig('container-ecr-framework-gated').delivery });
    assert.ok(errorPaths(r1).includes('delivery'));
    const r2 = validateConfig({ ...rawConfig('source-only'), container: { dockerfile: 'Dockerfile', imageName: 'app' } });
    assert.ok(errorPaths(r2).includes('container'));
  });
});

describe('the config never holds a credential value', () => {
  // The two GitHub PAT fixtures are assembled at runtime from fragments: a
  // contiguous token-shaped literal in this file is indistinguishable from a
  // real leaked credential to GitHub push protection, which blocks the push.
  // The assembled values are exactly as token-shaped as the detector demands
  // (see GITHUB token patterns in onboarding/lib/config.mjs) — the detector
  // itself is untouched, and the tests below prove both are still refused.
  const CLASSIC_PAT = ['gh', 'p_', '0123456789', 'abcdefghij', 'ABCDEFGHIJ'].join('');
  const FINE_GRAINED_PAT = ['github', '_pat_', '11ABCDEFGHIJ', '_', '0123456789abcdef'].join('');
  const credentials = {
    'AWS access key ID': 'AKIAQYLPMN5HHHFPZAM2',
    'Slack bot token': 'xoxb-1234567890-abcdefghij',
    'Slack webhook': 'https://hooks.slack.com/services/T000/B000/XXXXXXXX',
    'GitHub PAT': CLASSIC_PAT,
    'fine-grained PAT': FINE_GRAINED_PAT,
    'private key': '-----BEGIN RSA PRIVATE KEY-----',
    'URL credentials': 'https://user:hunter2@example.com/repo'
  };

  it('the synthetic PATs are token-shaped, so the cases below are not vacuous', () => {
    assert.equal(CLASSIC_PAT.length, 34, 'a classic PAT is the 4-character prefix plus 30 alphanumerics');
    assert.match(CLASSIC_PAT, /^gh[pousr]_[A-Za-z0-9]{30,}$/);
    assert.match(FINE_GRAINED_PAT, /^github_pat_[A-Za-z0-9_]{20,}$/);
    assert.equal(findSecretValues({ a: CLASSIC_PAT, b: FINE_GRAINED_PAT }).length, 2);
  });
  for (const [kind, value] of Object.entries(credentials)) {
    it(`refuses a ${kind} anywhere in the file, on load`, () => {
      const result = validateConfig(rawConfig('source-only', { notifications: { slack: { enabled: true, githubSecretName: 'SECURITY_NOTIFY_SLACK_URL' } }, repository: { slug: 'acme/app', defaultBranch: value } }));
      assert.ok(result.errors.some((e) => /non-secret/.test(e.message)), `${kind} was not flagged: ${JSON.stringify(result.errors)}`);
    });
  }

  it('refuses to SERIALIZE a config holding a credential, even if validation was bypassed', () => {
    const tampered = config('source-only');
    tampered.gitleaks = { mode: 'default', note: 'xoxb-1234567890-abcdefghij' };
    assert.throws(() => serializeConfig(tampered), /credential VALUES/);
  });

  it('records secret NAMES and resource ARNs, which are configuration', () => {
    const ecr = config('container-ecr-framework-gated', { notifications: { slack: { enabled: true, githubSecretName: 'TEAM_SLACK_WEBHOOK' } } });
    assert.deepEqual(findSecretValues(ecr), []);
    const text = serializeConfig(ecr);
    assert.match(text, /githubSecretName: TEAM_SLACK_WEBHOOK/);
    assert.ok(!/hooks\.slack\.com/.test(text));
  });

  it('refuses a GITHUB_-prefixed or lowercase secret name', () => {
    for (const name of ['GITHUB_TOKEN', 'slack_url']) {
      const result = validateConfig(rawConfig('source-only', { notifications: { slack: { enabled: true, githubSecretName: name } } }));
      assert.ok(errorPaths(result).includes('notifications.slack.githubSecretName'), name);
    }
  });
});

describe('the framework ref is an exact commit', () => {
  it('accepts a full 40-character commit SHA', () => {
    assert.deepEqual(errorPaths(validateConfig(rawConfig('source-only', { framework: { ref: REF } }))), []);
  });

  // Tags — even vX.Y.Z — can be moved, and the generator validates against
  // exactly one commit's contracts, so nothing weaker than a SHA is admitted.
  for (const ref of ['v1', 'v1.2.3', 'main', 'HEAD', '0683037', REF.toUpperCase(), `${REF}0`]) {
    it(`refuses '${ref}'`, () => {
      assert.ok(errorPaths(validateConfig(rawConfig('source-only', { framework: { ref } }))).includes('framework.ref'));
    });
  }

  it('has no moving-ref escape hatch', () => {
    const result = validateConfig(rawConfig('source-only', { framework: { ref: 'v1', allowMovingRef: true } }));
    assert.ok(errorPaths(result).includes('framework.allowMovingRef'));
    assert.ok(errorPaths(result).includes('framework.ref'));
  });
});

describe('the rollout invariants live in the schema, not only in the commands', () => {
  it('refuses gateMode enforce without an accepted baseline (so hand-editing cannot skip promote)', () => {
    const result = validateConfig(rawConfig('source-only', { rollout: { gateMode: 'enforce' } }));
    assert.match(errorsAt(result, 'rollout.gateMode'), /requires semgrep.baseline.state: accepted/);
  });

  it('allows enforce once the baseline is accepted', () => {
    const result = validateConfig(rawConfig('source-only', { rollout: { gateMode: 'enforce' }, semgrep: { baseline: { state: 'accepted' } } }));
    assert.deepEqual(result.errors, []);
  });
});

describe('scanner scope decisions', () => {
  it('defaults Semgrep to the whole repository', () => {
    const { config: c } = validateConfig(rawConfig('source-only', { semgrep: { roots: undefined } }));
    assert.deepEqual(c.semgrep.roots, ['.']);
  });

  it('refuses a catch-all ignore pattern and warns on excluding tests, migrations or IaC', () => {
    const catchAll = validateConfig(rawConfig('source-only', { semgrep: { ignore: { managed: true, patterns: ['**'] } } }));
    assert.ok(catchAll.errors.some((e) => /excludes everything/.test(e.message)));
    for (const pattern of ['tests/', 'migrations/', 'terraform/', '*_test.py']) {
      const result = validateConfig(rawConfig('source-only', { semgrep: { ignore: { managed: true, patterns: [pattern] } } }));
      assert.deepEqual(result.errors, [], pattern);
      assert.ok(result.warnings.some((w) => /deliberate, reviewed decision/.test(w.message)), `${pattern} should warn`);
    }
  });

  it('refuses a Gitleaks allowlist that matches everything', () => {
    const result = validateConfig(
      rawConfig('source-only', {
        gitleaks: { mode: 'managed', path: '.gitleaks.toml', customRules: [], allowlists: [{ description: 'noise', paths: ['.*'] }] }
      })
    );
    assert.ok(result.errors.some((e) => /broad allowlist/.test(e.message)));
  });

  it('refuses scanner-config keys that the chosen Gitleaks mode would silently ignore', () => {
    const result = validateConfig(rawConfig('source-only', { gitleaks: { mode: 'default', customRules: [{ id: 'x-rule', description: 'd', regex: 'X[0-9]{8}' }] } }));
    assert.ok(errorPaths(result).includes('gitleaks.customRules'));
  });

  it('has no local dependency-gap override: an acknowledgement section is an unknown key', () => {
    const gap = { path: 'svc/package-lock.json', gap: 'osv-only', reason: 'covered by OSV-Scanner recursively', owner: '@acme/sec', expires: '2999-01-01' };
    const result = validateConfig({ ...rawConfig('source-only'), dependencies: { acknowledgedGaps: [gap] } });
    assert.ok(errorPaths(result).includes('config.dependencies'), JSON.stringify(result.errors));
  });
});

describe('credential separation in the delivery config', () => {
  it('refuses one role for both push and deploy', () => {
    const result = validateConfig(rawConfig('container-ecr-framework-gated', { delivery: { roles: { deployRoleArn: PUSH_ROLE } } }));
    assert.match(errorsAt(result, 'delivery.roles.deployRoleArn'), /no single role may both push an image and deploy it/);
  });

  it('refuses a role in another account', () => {
    const result = validateConfig(
      rawConfig('container-ecr-framework-gated', { delivery: { roles: { pushScanRoleArn: 'arn:aws:iam::999999999999:role/x' } } })
    );
    assert.ok(errorPaths(result).includes('delivery.roles.pushScanRoleArn'));
  });

  it('refuses shell-unsafe values that reach the instance (container name, port)', () => {
    for (const ssm of [{ containerName: 'app;rm -rf /' }, { appPort: '80 && id' }, { appPort: '70000' }]) {
      const result = validateConfig(rawConfig('container-ecr-framework-gated', { delivery: { ssm } }));
      assert.ok(result.errors.length > 0, JSON.stringify(ssm));
    }
  });

});

describe('break-glass is not generated by Phase 1', () => {
  for (const mode of ['existing', 'provision', 'enabled']) {
    it(`refuses breakGlass.mode '${mode}' and explains why`, () => {
      const result = validateConfig(rawConfig('source-only', { breakGlass: { mode } }));
      assert.match(errorsAt(result, 'breakGlass.mode'), /not supported by ssd-onboard Phase 1/);
    });
  }

  it('refuses break-glass identifiers, so none can be wired by accident', () => {
    const result = validateConfig(rawConfig('source-only', { breakGlass: { mode: 'disabled', functionName: 'break-glass-ci' } }));
    assert.ok(errorPaths(result).includes('breakGlass.functionName'));
  });
});

describe('canonical serialization', () => {
  it('round-trips every profile exactly', () => {
    for (const profile of ['source-only', 'container-self-managed', 'container-ecr-framework-gated']) {
      const original = config(profile);
      const text = serializeConfig(original);
      const { config: reparsed, errors } = parseConfig(text);
      assert.deepEqual(errors, [], profile);
      assert.deepEqual(reparsed, original, profile);
      assert.equal(serializeConfig(reparsed), text, `${profile} serialization must be stable`);
    }
  });

  it('writes the account ID quoted, so no YAML reader turns it into a number', () => {
    assert.match(serializeConfig(config('container-ecr-framework-gated')), /accountId: '012345678901'/);
  });
});
