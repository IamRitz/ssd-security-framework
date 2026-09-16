// Structural guards on the FRAMEWORK's own workflows.
//
// Two classes of regression are invisible at runtime and so are asserted here:
//
//  1. The credential boundary — a `secrets: inherit` or an `id-token` added "to
//     make it work" fails nothing and looks green.
//  2. THE EXTRACTION ITSELF — every reusable workflow must load its scripts from
//     the toolkit it checks out, and must move that toolkit out of the scanned
//     workspace first. A single `node security/scripts/...` reintroduces the
//     coupling that made these workflows unusable outside their home repo, and
//     a missing relocation silently starts scanning the framework's own code as
//     if it were the consumer's.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

const WORKFLOW_DIR = '.github/workflows';

const read = (file) => readFileSync(join(WORKFLOW_DIR, file), 'utf8');
// Comments explain these rules; only the executable body is asserted against them.
const readExecutable = (file) =>
  read(file)
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');

const REUSABLE = readdirSync(WORKFLOW_DIR).filter(
  (name) => name.startsWith('_') && name.endsWith('.yml')
);

// Reusable workflows that must never hold cloud credentials. `_ecr-collect.yml`
// is the registry adapter; `_source-security.yml`'s gate job may assume the
// narrowly scoped break-glass invoker role after eligibility is confirmed.
const CREDENTIAL_FREE = ['_image-scan-prepush.yml', '_artifact-gate.yml', '_conformance.yml'];

describe('the framework ships the expected reusable workflows', () => {
  it('has all five, and they are workflow_call only', () => {
    assert.deepEqual(REUSABLE.sort(), [
      '_artifact-gate.yml',
      '_conformance.yml',
      '_ecr-collect.yml',
      '_image-scan-prepush.yml',
      '_source-security.yml'
    ]);
    for (const file of REUSABLE) {
      const source = readExecutable(file);
      assert.match(source, /^on:\n {2}workflow_call:/m, `${file} must be workflow_call only`);
      for (const trigger of ['push:', 'pull_request:', 'schedule:']) {
        assert.ok(
          !new RegExp(`^ {2}${trigger}`, 'm').test(source),
          `${file} must not declare its own ${trigger} trigger`
        );
      }
    }
  });
});

describe('the toolkit no longer travels with the consumer', () => {
  for (const file of REUSABLE) {
    it(`${file} runs every script from the checked-out toolkit`, () => {
      const source = readExecutable(file);

      // The regression this guards: a path resolved against the CALLING repo's
      // checkout, which only works inside the framework's own repository.
      const consumerRelative = [...source.matchAll(/node\s+["']?(?!\$)([A-Za-z0-9_./-]*scripts\/[A-Za-z0-9_.-]+\.mjs)/g)];
      assert.deepEqual(
        consumerRelative.map((match) => match[1]),
        [],
        `${file} invokes a script by a consumer-relative path; it must use "$SSD_TOOLKIT/scripts/..."`
      );
    });

    it(`${file} checks the framework out and pins a non-empty ref`, () => {
      const source = readExecutable(file);
      assert.match(source, /repository: \$\{\{ inputs\.toolkit_repository \}\}/, 'must check out the toolkit repo');
      assert.match(source, /ref: \$\{\{ inputs\.toolkit_ref \}\}/, 'must check out at the toolkit ref');
      // An empty ref would silently resolve to the framework's default branch —
      // an unpinned, moving dependency in a security control.
      assert.match(
        source,
        /toolkit_ref is empty/,
        'must refuse to resolve the toolkit from a default branch'
      );
    });

    it(`${file} asserts the toolkit's major version`, () => {
      const source = readExecutable(file);
      assert.match(source, /SSD_REQUIRED_TOOLKIT_MAJOR/, 'must declare the major it is written against');
      assert.match(source, /VERSION/, 'must read the toolkit VERSION file');
    });

    it(`${file} moves the toolkit out of the scanned workspace`, () => {
      // The workspace must be byte-identical to the consumer's own checkout when
      // scanners run. Semgrep's default path is `.` and OSV-Scanner walks the
      // tree recursively; a toolkit left in place is scanned as consumer code.
      const source = readExecutable(file);
      assert.match(
        source,
        /mv \.ssd-toolkit-checkout "\$RUNNER_TEMP\/ssd-toolkit"/,
        `${file} must relocate the toolkit under RUNNER_TEMP`
      );
    });
  }

  it('the scanning workflow proves the workspace is clean before scanning', () => {
    // Only _source-security.yml runs scanners over the workspace, so it carries
    // the explicit assertion.
    const source = readExecutable('_source-security.yml');
    const assertions = source.match(/Confirm the workspace holds no framework files/g) ?? [];
    assert.equal(
      assertions.length,
      3,
      'each of the three scanner jobs must assert the workspace holds no framework files'
    );
  });
});

describe('the credential boundary', () => {
  for (const file of CREDENTIAL_FREE) {
    it(`${file} can assume no cloud role`, () => {
      const source = readExecutable(file);
      // `id-token: write` is what makes OIDC role assumption possible at all.
      assert.ok(!/id-token\s*:/.test(source), 'must not request an id-token');
      assert.ok(!/aws-actions\//.test(source), 'must not use an aws-actions action');
      assert.ok(!/role-to-assume/.test(source), 'must not assume a role');
    });
  }

  it('only approved workflows assume cloud roles', () => {
    const assuming = REUSABLE.filter((file) => /role-to-assume/.test(read(file)));
    assert.deepEqual(assuming.sort(), ['_ecr-collect.yml', '_source-security.yml']);
  });

  it('source-security loads no approval credential before confirming eligibility', () => {
    const source = readExecutable('_source-security.yml');
    const gate = source.slice(source.indexOf('  source-gate:'));
    const eligibility = gate.indexOf('Confirm the BLOCK is eligible before loading any approval credential');
    const oidc = gate.indexOf('Assume the break-glass invoker role (OIDC)');
    assert.ok(eligibility >= 0, 'eligibility check is missing');
    assert.ok(oidc >= 0, 'OIDC role-assumption step is missing');
    assert.ok(eligibility < oidc, 'OIDC credentials must only be loaded after eligibility is confirmed');
  });

  it('no workflow uses `secrets: inherit`', () => {
    for (const file of readdirSync(WORKFLOW_DIR).filter((name) => name.endsWith('.yml'))) {
      assert.ok(
        !/secrets\s*:\s*inherit/.test(readExecutable(file)),
        `${file} must not pass every repo secret into a called workflow`
      );
    }
  });

  it('only source-security declares a secret, and only the break-glass one', () => {
    const source = read('_source-security.yml');
    const declared = [...source.matchAll(/^ {6}([a-z0-9_]+):\s*$/gm)]
      .map((match) => match[1])
      .filter((name) => source.includes(`secrets:\n      ${name}:`));
    assert.deepEqual(declared, ['break_glass_shared_secret']);
    for (const file of CREDENTIAL_FREE) {
      assert.ok(!/^ {4}secrets:/m.test(read(file)), `${file} must accept no secrets`);
    }
  });
});

describe('the artifact gate stays registry-neutral', () => {
  it('names no registry, so swapping registries touches only the collector', () => {
    const executable = readExecutable('_artifact-gate.yml');
    for (const term of [/\becr\b/i, /\bamazon\b/i, /\bgcr\b/i, /\backr\b/i, /\bdockerhub\b/i]) {
      assert.ok(!term.test(executable), `artifact gate must not reference ${term}`);
    }
  });
});

describe('capability declaration', () => {
  it('conformance accepts the three declared capabilities', () => {
    const source = readExecutable('_conformance.yml');
    for (const input of ['artifact_type:', 'registry:', 'deploy_target:']) {
      assert.match(source, new RegExp(`^ {6}${input}`, 'm'), `_conformance.yml must accept ${input}`);
    }
  });

  it('requires observed results rather than assuming controls ran', () => {
    const source = readExecutable('_conformance.yml');
    assert.match(source, /observed:[\s\S]*?required: true/, 'observed results must be required');
  });
});

const EXAMPLE_DIR = 'examples';
const EXAMPLES = readdirSync(EXAMPLE_DIR, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .flatMap((entry) =>
    readdirSync(join(EXAMPLE_DIR, entry.name))
      .filter((file) => file.endsWith('.yml'))
      .map((file) => join(EXAMPLE_DIR, entry.name, file))
  );

const example = (path) => readFileSync(path, 'utf8');

// Extracts one job's block from an example: everything from `  <id>:` up to the
// next top-level job key. No YAML parser is available here (the toolkit is
// dependency-free by design), and these are structural string assertions.
function jobBlock(source, jobId) {
  const start = source.indexOf(`\n  ${jobId}:\n`);
  if (start === -1) {
    return null;
  }
  const lines = source.slice(start + 1).split('\n');
  const block = [lines[0]];
  for (const line of lines.slice(1)) {
    if (/^ {2}[A-Za-z0-9_-]+:/.test(line)) {
      break;
    }
    block.push(line);
  }
  return block.join('\n');
}

describe('the example callers keep their version pins in sync', () => {
  // A reusable workflow cannot read its own ref, so a consumer states the
  // version twice: once in `uses: ...@v1` and once as `toolkit_ref: v1`. Drift
  // between them runs one version's workflow against another version's scripts.
  // The shipped examples are what people copy, so they are the one place this
  // must never be wrong.
  it('has example callers to check', () => {
    assert.ok(EXAMPLES.length >= 4, 'expected the PR and delivery examples to be present');
    assert.ok(
      EXAMPLES.includes(join('examples', 'container-ecr', 'deploy.yml')),
      'the framework must ship a canonical framework-gated delivery caller'
    );
  });

  for (const path of EXAMPLES) {
    it(`${path} pins one ref everywhere`, () => {
      const source = example(path);
      const usesRefs = [
        ...source.matchAll(/uses:\s*\S*ssd-security-framework\/\.github\/workflows\/\S+@(\S+)/g)
      ].map((match) => match[1]);
      const toolkitRefs = [...source.matchAll(/toolkit_ref:\s*(\S+)/g)].map((match) => match[1]);

      assert.ok(usesRefs.length > 0, 'example must call the framework');
      const distinct = [...new Set(usesRefs)];
      assert.equal(distinct.length, 1, `example mixes framework refs: ${distinct.join(', ')}`);
      assert.equal(
        toolkitRefs.length,
        usesRefs.length,
        'every framework call must pass toolkit_ref'
      );
      for (const ref of toolkitRefs) {
        assert.equal(ref, distinct[0], `toolkit_ref '${ref}' must match the uses: ref`);
      }

      // A direct checkout of the framework (the deploy example fetches
      // ssm-deploy.mjs this way) is the same version pin and must not drift.
      if (/repository: IamRitz\/ssd-security-framework/.test(source)) {
        const checkoutRefs = [
          ...source.matchAll(/repository: IamRitz\/ssd-security-framework\n\s*ref: (\S+)/g)
        ].map((match) => match[1]);
        assert.ok(checkoutRefs.length > 0, 'a framework checkout must pin a ref');
        for (const ref of checkoutRefs) {
          assert.equal(ref, distinct[0], `framework checkout ref '${ref}' must match the uses: ref`);
        }
      }
    });
  }
});

describe('the stable required check represents every control that gates the PR', () => {
  // The bug: `security-gate` needed only source-security, so a container PR
  // whose pre-push image gate reported BLOCK_DEPLOY could still satisfy branch
  // protection. The name promises "this PR is secure"; it has to mean it.
  const PR_EXAMPLES = EXAMPLES.filter((path) => path.endsWith('security.yml'));

  for (const path of PR_EXAMPLES) {
    const source = example(path);
    const gate = jobBlock(source, 'security-gate');
    const shipsContainer = jobBlock(source, 'image-security') !== null;

    it(`${path} publishes a literal, mode-independent check name`, () => {
      assert.ok(gate, 'every PR example must publish a security-gate job');
      const nameLine = /^ {4}name: (.*)$/m.exec(gate);
      assert.ok(nameLine, 'security-gate must set an explicit name');
      assert.equal(nameLine[1].trim(), 'security-gate');
      // A name computed from the mode would stop matching branch protection in
      // one of the two modes, silently protecting nothing.
      assert.ok(!nameLine[1].includes('${{'), 'the required check name must not be computed');
      assert.ok(!/gate_mode/.test(nameLine[1]), 'the name must not vary with gate_mode');
    });

    it(`${path} still reports when a dependency fails or is skipped`, () => {
      // Without always() the job is skipped, the required check never posts, and
      // the PR waits forever on a status that never arrives.
      assert.match(gate, /if: \$\{\{ always\(\) \}\}/, 'security-gate must use always()');
    });

    it(`${path} fails the aggregate when source security fails`, () => {
      assert.match(gate, /needs\.source-security\.result/, 'must read the source result');
      assert.match(gate, /SOURCE_RESULT" != "success"/, 'must fail on a non-success source result');
    });

    if (shipsContainer) {
      it(`${path} (container) also fails the aggregate when image security fails`, () => {
        assert.match(
          gate,
          /needs:\s*\n\s*- source-security\s*\n\s*- image-security/,
          'a container example must aggregate BOTH controls'
        );
        assert.match(gate, /needs\.image-security\.result/, 'must read the image result');
        assert.match(
          gate,
          /IMAGE_RESULT" != "success"/,
          'must fail on a non-success image result'
        );
      });

      it(`${path} (container) only tolerates a skipped image gate on the schedule`, () => {
        // The trap: the scheduled sweep builds no image, so image-security is
        // skipped there legitimately. Treating `skipped` as acceptable
        // unconditionally would let schedule-shaped behaviour redefine the PR
        // contract — a PR where the image job never ran would pass.
        assert.match(gate, /EVENT" = "schedule"/, 'must special-case the scheduled run');
        const scheduleBranch = gate.slice(gate.indexOf('EVENT" = "schedule"'));
        assert.match(
          scheduleBranch,
          /success\|skipped/,
          'skipped is acceptable only inside the schedule branch'
        );
        const beforeSchedule = gate.slice(0, gate.indexOf('EVENT" = "schedule"'));
        assert.ok(
          !/success\|skipped/.test(beforeSchedule),
          'skipped must never be accepted outside the schedule branch'
        );
      });
    } else {
      it(`${path} (source-only) does not require an image gate it never runs`, () => {
        assert.ok(
          !/image-security/.test(gate),
          'a source-only repo has no image control to aggregate'
        );
      });
    }
  }
});

describe('conformance evidence is lifecycle-aware', () => {
  it('no example claims a control passed in a phase that does not run it', () => {
    // The original bug: a PR reporting `gated-deploy: pass` with evidence
    // "runs on push to main" — a control that demonstrably did not execute.
    for (const path of EXAMPLES) {
      const source = example(path);
      const conformance = jobBlock(source, 'conformance');
      if (!conformance) {
        continue;
      }
      assert.match(conformance, /phase: (pr|delivery)/, `${path} must declare its phase`);

      if (/phase: pr/.test(conformance)) {
        for (const deliveryControl of ['registry-scan-collect', 'artifact-gate', 'gated-deploy']) {
          assert.ok(
            !new RegExp(`"${deliveryControl}":\\s*\\{"status":"pass"`).test(conformance),
            `${path} must not hard-code a pass for ${deliveryControl} on a PR`
          );
        }
        assert.ok(
          !/runs on push to main/.test(conformance),
          `${path} must not cite a future run as evidence`
        );
      }
    }
  });

  it('the delivery example proves the delivery controls with real job results', () => {
    const source = example(join('examples', 'container-ecr', 'deploy.yml'));
    const conformance = jobBlock(source, 'conformance');
    assert.match(conformance, /phase: delivery/);
    for (const [control, job] of [
      ['registry-scan-collect', 'ecr-collect'],
      ['artifact-gate', 'artifact-gate'],
      ['gated-deploy', 'deploy']
    ]) {
      assert.match(
        conformance,
        new RegExp(`"${control}":\\{"status":"\\$\\{\\{ needs\\.${job}\\.result \\}\\}"`),
        `${control} must be evidenced by the ${job} job's real result`
      );
    }
  });

  it('the delivery example keeps the digest chain unbroken', () => {
    const source = example(join('examples', 'container-ecr', 'deploy.yml'));
    // scan -> push
    assert.match(
      jobBlock(source, 'ecr-collect'),
      /expected_image_id: \$\{\{ needs\.image-security\.outputs\.image_id \}\}/,
      'the collector must assert the pushed image is the scanned image'
    );
    // push -> gate
    assert.match(
      jobBlock(source, 'artifact-gate'),
      /expected_digest: \$\{\{ needs\.ecr-collect\.outputs\.image_digest \}\}/,
      'the gate must re-assert the pushed manifest digest'
    );
    // gate -> deploy
    const deploy = jobBlock(source, 'deploy');
    assert.match(
      deploy,
      /IMAGE_DIGEST: \$\{\{ needs\.ecr-collect\.outputs\.image_digest \}\}/,
      'the deploy must pin the exact gated digest'
    );
    assert.match(deploy, /--image-digest/, 'the deploy must pull by digest, never by tag');
    assert.match(
      deploy,
      /needs:\s*\n\s*- artifact-gate/,
      'deploy must not start unless the artifact gate succeeded'
    );
  });

  it('the delivery example keeps build, registry, and deploy credentials apart', () => {
    const source = example(join('examples', 'container-ecr', 'deploy.yml'));
    const build = jobBlock(source, 'container-build');
    // Untrusted build/install code must never share a job with a cloud role.
    assert.ok(!/id-token/.test(build), 'the build job must hold no OIDC token');
    assert.ok(!/role-to-assume/.test(build), 'the build job must assume no role');
    assert.ok(!/aws-actions/.test(build), 'the build job must not touch AWS');

    const artifactGate = jobBlock(source, 'artifact-gate');
    assert.ok(!/id-token/.test(artifactGate), 'the artifact gate must hold no credentials');

    // The registry role and the deploy role live in different jobs.
    assert.match(jobBlock(source, 'ecr-collect'), /AWS_PUSH_SCAN_ROLE_ARN/);
    assert.ok(
      !/AWS_DEPLOY_ROLE_ARN/.test(jobBlock(source, 'ecr-collect')),
      'the registry job must not hold the deploy role'
    );
    assert.match(jobBlock(source, 'deploy'), /AWS_DEPLOY_ROLE_ARN/);
    assert.ok(
      !/AWS_PUSH_SCAN_ROLE_ARN/.test(jobBlock(source, 'deploy')),
      'the deploy job must hold no registry credentials'
    );
  });
});

describe('baseline bootstrap is explicit and refuses to run unverified', () => {
  const source = readExecutable('_source-security.yml');

  it('is opt-in through a dedicated input', () => {
    assert.match(source, /^ {6}bootstrap_baseline:/m, 'bootstrap must be an explicit input');
    assert.match(source, /default: false/, 'bootstrap must default off');
  });

  it('is confined to onboarding mode', () => {
    // Bootstrap evaluates against an empty accepted set, so in `enforce` it would
    // block on the very backlog the baseline exists to accept.
    assert.match(source, /Refuse baseline bootstrap outside onboarding/);
    assert.match(
      source,
      /inputs\.bootstrap_baseline && inputs\.gate_mode != 'log-only'/,
      'bootstrap must refuse to run outside log-only'
    );
  });

  it('passes --bootstrap to the gate only when asked', () => {
    assert.match(
      source,
      /if \[ "\$BOOTSTRAP" = "true" \]; then[\s\S]*?args\+=\(--bootstrap\)/,
      'the flag must be conditional, not always present'
    );
  });

  it('fails loudly when a bootstrap run could not be trusted', () => {
    // In log-only nothing else fails, so a bootstrap that silently produced no
    // baseline would look like a success.
    assert.match(source, /Fail a bootstrap run whose scans could not be trusted/);
    assert.match(
      source,
      /inputs\.bootstrap_baseline && steps\.verdict\.outputs\.integrity_trusted != 'true'/,
      'an untrusted bootstrap must fail the job'
    );
  });

  it('generates the candidate only from a trusted run', () => {
    assert.match(
      source,
      /inputs\.bootstrap_baseline && steps\.verdict\.outputs\.integrity_trusted == 'true'/,
      'generation must be gated on scanner integrity'
    );
    assert.match(source, /generate-semgrep-baseline\.mjs/);
    assert.match(source, /--rulesets/, 'the baseline must record the rulesets that produced it');
  });
});

describe('synthetic break-glass runs are isolated from production by construction', () => {
  const source = readExecutable('_source-security.yml');
  const gate = source.slice(source.indexOf('  source-gate:'));

  it('declares dedicated synthetic transport inputs', () => {
    for (const input of [
      'synthetic_break_glass_lambda_function',
      'synthetic_break_glass_lambda_role_arn',
      'synthetic_break_glass_aws_region'
    ]) {
      assert.match(source, new RegExp(`^ {6}${input}:`, 'm'), `must declare ${input}`);
    }
  });

  it('refuses a synthetic run with no isolated configuration, for BOTH transports', () => {
    const guard = gate.slice(
      gate.indexOf('Require an isolated break-glass configuration for a synthetic run')
    );
    assert.match(guard, /synthetic_break_glass_lambda_function/, 'lambda needs a test function');
    assert.match(guard, /synthetic_break_glass_lambda_role_arn/, 'lambda needs a test role');
    assert.match(guard, /break_glass_notify_url/, 'http still needs explicit dev endpoints');
  });

  it('rejects reusing the production function or role for a synthetic run', () => {
    // Isolation is proven by the identifiers differing, never inferred from a
    // name containing "test".
    assert.match(gate, /SYNTH_FUNCTION" = "\$PROD_FUNCTION"/, 'must reject the production function');
    assert.match(gate, /SYNTH_ROLE" = "\$PROD_ROLE"/, 'must reject the production role');
  });

  it('fails BEFORE any credential is assumed or any broker invoked', () => {
    const guardIndex = gate.indexOf('Require an isolated break-glass configuration');
    const evaluateIndex = gate.indexOf('Evaluate security policy');
    const oidcIndex = gate.indexOf('Assume the break-glass invoker role (OIDC)');
    const notifyIndex = gate.indexOf('Request break-glass decision');

    assert.ok(guardIndex >= 0, 'the isolation guard is missing');
    assert.ok(guardIndex < evaluateIndex, 'isolation must be proven before the gate even runs');
    assert.ok(guardIndex < oidcIndex, 'isolation must be proven before OIDC role assumption');
    assert.ok(guardIndex < notifyIndex, 'isolation must be proven before any broker invocation');
  });

  it('hands the OIDC action the RESOLVED role, never the raw production input', () => {
    // The whole point: a synthetic run must be unable to assume the production
    // invoker role even if someone passes it.
    assert.match(gate, /role-to-assume: \$\{\{ env\.SSD_BG_ROLE \}\}/);
    assert.ok(
      !/role-to-assume: \$\{\{ inputs\.break_glass_lambda_role_arn \}\}/.test(gate),
      'the raw production role input must not reach the OIDC action'
    );
  });

  it('sends the broker calls to the resolved function, not the raw input', () => {
    assert.match(gate, /BREAK_GLASS_FUNCTION_NAME: \$\{\{ env\.SSD_BG_FUNCTION \}\}/);
    assert.ok(
      !/BREAK_GLASS_FUNCTION_NAME: \$\{\{ inputs\.break_glass_lambda_function \}\}/.test(gate),
      'the raw production function input must not reach the broker client'
    );
  });

  it('still confirms eligibility before resolving or assuming anything', () => {
    const eligibility = gate.indexOf(
      'Confirm the BLOCK is eligible before loading any approval credential'
    );
    const resolve = gate.indexOf('Validate break-glass transport and resolve the effective broker');
    const oidc = gate.indexOf('Assume the break-glass invoker role (OIDC)');
    assert.ok(eligibility >= 0 && resolve > eligibility && oidc > resolve);
  });
});
