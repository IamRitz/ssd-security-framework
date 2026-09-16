// The conformance report's whole job is to distinguish four outcomes that a
// naive report collapses into "skipped":
//
//   applied / not-applicable / exempt / failed
//
// The distinction between NOT-APPLICABLE and EXEMPT is the one that carries
// meaning for a reviewer: N/A is a stable fact about what the repo is, exempt is
// debt with an owner and a deadline. These tests exist to stop the two from
// blurring back together.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CONTROLS,
  buildConformance,
  renderMarkdown,
  resolveCapabilities,
  resolvePhase
} from '../security/scripts/conformance.mjs';

const CONTAINER_REPO = {
  artifact_type: 'container',
  registry: 'ecr',
  deploy_target: 'framework-gated'
};

// Every control reported as passing, so a test can focus on the one thing it
// changes rather than on incidental failures.
function allObserved() {
  return Object.fromEntries(
    CONTROLS.map((control) => [control.id, { status: 'pass', evidence: 'test' }])
  );
}

const statusOf = (report, id) => report.controls.find((control) => control.id === id);

describe('capability declaration', () => {
  it('defaults to the least-capable repository', () => {
    // An undeclared repo must not be assumed to ship containers: guessing
    // "container" would mark image controls applicable and fail every library.
    assert.deepEqual(resolveCapabilities(), {
      artifact_type: 'none',
      registry: 'none',
      deploy_target: 'none'
    });
  });

  it('accepts a fully declared container repository', () => {
    assert.deepEqual(resolveCapabilities(CONTAINER_REPO), CONTAINER_REPO);
  });

  it('rejects an unknown capability name', () => {
    assert.throws(
      () => resolveCapabilities({ artifact_kind: 'container' }),
      /unknown capability 'artifact_kind'/
    );
  });

  it('rejects a value outside the closed set', () => {
    // A typo must fail closed. Silently treating `containr` as "none" would mark
    // the image controls N/A and report a green conformance for an unscanned image.
    assert.throws(
      () => resolveCapabilities({ artifact_type: 'containr' }),
      /artifact_type='containr' is not one of/
    );
  });

  it('rejects a registry without a container to push', () => {
    assert.throws(
      () => resolveCapabilities({ artifact_type: 'library', registry: 'ecr' }),
      /registry=ecr requires artifact_type=container/
    );
  });

  it('rejects a framework-gated deploy with no registry', () => {
    assert.throws(
      () =>
        resolveCapabilities({
          artifact_type: 'container',
          registry: 'none',
          deploy_target: 'framework-gated'
        }),
      /deploy_target=framework-gated requires a registry/
    );
  });

  it('rejects a framework-gated deploy of a non-container', () => {
    assert.throws(
      () => resolveCapabilities({ artifact_type: 'archive', deploy_target: 'framework-gated' }),
      /deploy_target=framework-gated requires artifact_type=container/
    );
  });
});

describe('not-applicable is a reasoned fact, not a skip', () => {
  it('reports image controls as N/A for a repo that ships no container', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'none' }),
      observed: { 'secret-scan': { status: 'pass' }, 'dependency-scan': { status: 'pass' },
        sast: { status: 'pass' }, 'source-gate': { status: 'pass' } }
    });

    for (const id of ['image-scan-prepush', 'registry-scan-collect', 'artifact-gate']) {
      const control = statusOf(report, id);
      assert.equal(control.status, 'not-applicable', `${id} must be N/A`);
      // The reason must name the capability that made it N/A, so a reader can
      // tell this from a control someone switched off.
      assert.match(control.reason, /artifact_type=none/);
    }
  });

  it('does not count N/A controls as failures', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'none' }),
      observed: { 'secret-scan': { status: 'pass' }, 'dependency-scan': { status: 'pass' },
        sast: { status: 'pass' }, 'source-gate': { status: 'pass' } }
    });

    assert.equal(report.summary.failed, 0);
    assert.ok(report.summary.notApplicable >= 3);
  });

  it('distinguishes "no registry" from "no container" in the reason', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'container', registry: 'none' }),
      observed: allObserved()
    });

    // The image still gets scanned pre-push — it exists. Only the registry-side
    // controls are N/A, and for a different reason than "no container".
    assert.equal(statusOf(report, 'image-scan-prepush').status, 'applied');
    assert.match(statusOf(report, 'artifact-gate').reason, /registry=none/);
  });

  it('reports a self-managed deploy as N/A rather than a gap', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({
        artifact_type: 'container',
        registry: 'ecr',
        deploy_target: 'self-managed'
      }),
      observed: allObserved()
    });

    const deploy = statusOf(report, 'gated-deploy');
    assert.equal(deploy.status, 'not-applicable');
    assert.match(deploy.reason, /self-managed/);
  });

  it('warns when a control the capabilities exclude still reported a result', () => {
    // The declaration and the caller workflow disagree. Trusting either silently
    // is how a repo ends up believing it scans an image it does not build.
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'library' }),
      observed: { ...allObserved() }
    });

    assert.ok(
      report.warnings.some((warning) => /image-scan-prepush/.test(warning)),
      'a result for an inapplicable control must be surfaced'
    );
  });
});

describe('exempt is debt, and it expires closed', () => {
  const future = '2999-01-01';
  const past = '2000-01-01';

  it('records an exemption with its owner and expiry', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: {},
      exemptions: [
        {
          control: 'image-scan-prepush',
          reason: 'base image pending platform upgrade',
          owner: 'security-eng',
          expires: future,
          expiresAt: Date.parse(future)
        }
      ],
      breakGlassEnabled: true
    });

    const control = statusOf(report, 'image-scan-prepush');
    assert.equal(control.status, 'exempt');
    assert.equal(control.owner, 'security-eng');
    assert.equal(control.expires, future);
    // Crucially NOT reported as not-applicable: the control applies here.
    assert.notEqual(control.status, 'not-applicable');
  });

  it('stops honouring an exemption after its expiry', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: {},
      exemptions: [
        {
          control: 'image-scan-prepush',
          reason: 'temporary',
          owner: 'security-eng',
          expires: past,
          expiresAt: Date.parse(past)
        }
      ],
      breakGlassEnabled: true
    });

    const control = statusOf(report, 'image-scan-prepush');
    assert.equal(control.status, 'failed', 'an expired exemption must grant nothing');
    assert.ok(report.warnings.some((warning) => /expired/.test(warning)));
  });

  it('never lets an exemption apply to a control that is already N/A', () => {
    // Exempting something that cannot happen would quietly inflate the exempt
    // count and make a library look like it is carrying container debt.
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'library' }),
      observed: {},
      exemptions: [
        {
          control: 'image-scan-prepush',
          reason: 'irrelevant here',
          owner: 'security-eng',
          expires: future,
          expiresAt: Date.parse(future)
        }
      ]
    });

    assert.equal(statusOf(report, 'image-scan-prepush').status, 'not-applicable');
    assert.equal(report.summary.exempt, 0);
  });
});

describe('applicable controls must produce evidence', () => {
  it('fails a control that applies but reported nothing', () => {
    // Absence of evidence is not evidence the control ran.
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'none' }),
      observed: {}
    });

    assert.equal(statusOf(report, 'source-gate').status, 'failed');
    assert.match(statusOf(report, 'source-gate').reason, /reported no result/);
  });

  it('fails a control whose observed result did not pass', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'none' }),
      observed: { ...allObserved(), 'source-gate': { status: 'failure' } }
    });

    assert.equal(statusOf(report, 'source-gate').status, 'failed');
  });

  it('treats break-glass as N/A when no approval channel is configured', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'none' }),
      observed: {},
      breakGlassEnabled: false
    });

    const control = statusOf(report, 'break-glass');
    assert.equal(control.status, 'not-applicable');
    assert.match(control.reason, /break_glass_enabled=false/);
  });
});

describe('lifecycle: a control that did not run in this phase never reports pass', () => {
  // The bug this prevents: a PR conformance report claiming
  // `gated-deploy: pass, evidence: "runs on push to main"`. That control did not
  // execute in that workflow, so the claim is fabricated — but it is also not
  // N/A, because the repository genuinely requires it.
  const DELIVERY_CONTROLS = ['registry-scan-collect', 'artifact-gate', 'gated-deploy'];

  // Everything a PR run can actually prove for a container repo.
  const SOURCE_OBSERVED = {
    'secret-scan': { status: 'pass' },
    'dependency-scan': { status: 'pass' },
    sast: { status: 'pass' },
    'source-gate': { status: 'pass' },
    'image-scan-prepush': { status: 'pass' }
  };
  // Where break-glass is ENABLED it is an ordinary PR-phase control and needs
  // evidence like any other — omitting it is a `failed`, not a free pass.
  const prObserved = { ...SOURCE_OBSERVED, 'break-glass': { status: 'pass' } };

  it('defers delivery controls on a PR instead of passing or N/A-ing them', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: prObserved,
      breakGlassEnabled: true,
      phase: 'pr'
    });

    for (const id of DELIVERY_CONTROLS) {
      const control = statusOf(report, id);
      assert.equal(control.status, 'deferred', `${id} must be deferred on a PR`);
      // Still required of this repository — that is the difference from N/A.
      assert.equal(control.appliesToRepository, true);
      assert.match(control.reason, /delivery phase/);
    }
    assert.equal(report.summary.failed, 0, 'a deferred control is not a failure');
    assert.equal(report.summary.deferred, DELIVERY_CONTROLS.length);
  });

  it('answers "what does this repo require" independently of this run', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: prObserved,
      breakGlassEnabled: true,
      phase: 'pr'
    });

    // 9 controls, all applicable to a full framework-gated container repo.
    assert.equal(report.summary.requiredByRepository, CONTROLS.length);
    assert.equal(
      report.summary.applied + report.summary.deferred,
      CONTROLS.length,
      'every required control is either proven here or proven in the delivery run'
    );
  });

  it('requires real evidence for delivery controls in the delivery phase', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: prObserved, // no delivery evidence supplied
      breakGlassEnabled: true,
      phase: 'delivery'
    });

    for (const id of DELIVERY_CONTROLS) {
      const control = statusOf(report, id);
      assert.equal(control.status, 'failed', `${id} must fail without delivery evidence`);
      assert.match(control.reason, /reported no result/);
    }
    assert.equal(report.summary.failed, DELIVERY_CONTROLS.length);
  });

  it('marks delivery controls applied when the delivery run proves them', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: {
        ...prObserved,
        'registry-scan-collect': { status: 'success', evidence: 'ecr-collect job' },
        'artifact-gate': { status: 'success', evidence: 'artifact-gate job' },
        'gated-deploy': { status: 'success', evidence: 'deploy job, digest-pinned' }
      },
      breakGlassEnabled: true,
      phase: 'delivery'
    });

    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.deferred, 0);
    assert.equal(report.summary.applied, CONTROLS.length);
    assert.equal(statusOf(report, 'gated-deploy').evidence, 'deploy job, digest-pinned');
  });

  it('warns when a caller claims a result for a control this phase does not run', () => {
    // Exactly the old container-ecr example: "gated-deploy: pass, runs on push to main".
    const report = buildConformance({
      capabilities: resolveCapabilities(CONTAINER_REPO),
      observed: {
        ...prObserved,
        'gated-deploy': { status: 'pass', evidence: 'runs on push to main' }
      },
      breakGlassEnabled: true,
      phase: 'pr'
    });

    assert.equal(statusOf(report, 'gated-deploy').status, 'deferred', 'the claim is not honoured');
    assert.ok(
      report.warnings.some((warning) => /gated-deploy/.test(warning) && /did not execute/.test(warning)),
      'a fabricated result must be surfaced as a warning'
    );
  });

  it('a self-managed container repo defers nothing it does not own', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({
        artifact_type: 'container',
        registry: 'none',
        deploy_target: 'self-managed'
      }),
      // break-glass is disabled here, so it is N/A and deliberately gets no
      // evidence — claiming a result for an N/A control would be a warning.
      observed: SOURCE_OBSERVED,
      phase: 'pr'
    });

    // Registry/deploy are N/A (not this repo's), so nothing is deferred to a
    // delivery run this framework never performs.
    for (const id of DELIVERY_CONTROLS) {
      assert.equal(statusOf(report, id).status, 'not-applicable', `${id} must be N/A`);
    }
    assert.equal(report.summary.deferred, 0);
    assert.equal(report.summary.failed, 0);
    // The pre-push image scan still applies and still ran.
    assert.equal(statusOf(report, 'image-scan-prepush').status, 'applied');
  });

  it('a source-only repo requires only source controls', () => {
    const report = buildConformance({
      capabilities: resolveCapabilities({ artifact_type: 'library' }),
      observed: {
        'secret-scan': { status: 'pass' },
        'dependency-scan': { status: 'pass' },
        sast: { status: 'pass' },
        'source-gate': { status: 'pass' }
      },
      phase: 'pr'
    });

    assert.equal(report.summary.failed, 0);
    assert.equal(report.summary.deferred, 0);
    assert.equal(report.summary.requiredByRepository, 4);
    assert.equal(report.summary.applied, 4);
  });

  it('rejects an unrecognized phase rather than defaulting to pr', () => {
    // Defaulting would defer every delivery control and report a green run.
    assert.throws(() => resolvePhase('deploy'), /phase 'deploy' is not one of/);
    assert.equal(resolvePhase(''), 'pr');
    assert.equal(resolvePhase('delivery'), 'delivery');
  });
});

describe('the rendered report keeps the outcomes visually distinct', () => {
  it('renders N/A and exempt differently, and shows the exemption owner', () => {
    const future = '2999-01-01';
    const markdown = renderMarkdown(
      buildConformance({
        capabilities: resolveCapabilities({ artifact_type: 'container', registry: 'none' }),
        observed: allObserved(),
        exemptions: [
          {
            control: 'image-scan-prepush',
            reason: 'pending base image',
            owner: 'security-eng',
            expires: future,
            expiresAt: Date.parse(future)
          }
        ]
      })
    );

    assert.match(markdown, /N\/A/);
    assert.match(markdown, /exempt/);
    assert.match(markdown, /owner security-eng/);
    assert.match(markdown, /artifact_type=container/);
  });
});
