// Capability-aware, LIFECYCLE-AWARE conformance reporting.
//
// Consumer repositories differ in what they SHIP, not just in how they are
// configured. A library has no container to scan; a repo with its own delivery
// pipeline has no framework-gated deploy. Reporting those controls as "skipped"
// makes a conformance report useless, because it cannot be distinguished from a
// control that was switched off.
//
// They also differ in WHEN a control runs. A pull request cannot execute a
// registry scan or a deploy — those happen on the delivery run. Reporting them
// as `pass` on a PR is a fabricated result; reporting them as N/A is a lie of a
// different kind, because they ARE required of that repository.
//
// So the model answers two separate questions:
//
//   1. What security controls does this repository require?
//      -> every control whose `appliesToRepository` is true.
//   2. Which required controls actually executed successfully in THIS run?
//      -> every control whose status is `applied`.
//
// Every control resolves to exactly one of:
//
//   applied         the control ran in this phase, and its result is recorded
//   deferred        applies to the repo, but is not expected in THIS phase.
//                   Required by the delivery lifecycle, proven by another run.
//   not-applicable  the repo's declared capabilities mean the control has no
//                   subject. A STABLE FACT about what this repo is. Carries a
//                   reason naming the capability that made it so.
//   exempt          the control applies and is deliberately not being enforced.
//                   DEBT: carries an owner and an expiry, and expires closed.
//   failed          the control applies, is expected now, is not exempt, and did
//                   not pass — including "produced no evidence at all".
//
// `not-applicable`, `deferred` and `exempt` are deliberately different words for
// deliberately different things. A library will never grow an image to scan; a
// PR simply has not reached the deploy yet; an exempted image gate is risk
// somebody agreed to revisit. A report that renders them all as "skipped" tells
// a reviewer nothing.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// The declared capability vocabulary. Closed sets: an unrecognized value is a
// configuration error and fails closed, never a silent "treat it as none",
// which would quietly mark real controls not-applicable.
export const CAPABILITY_VALUES = {
  artifact_type: ['container', 'archive', 'library', 'none'],
  registry: ['ecr', 'none'],
  deploy_target: ['framework-gated', 'self-managed', 'none']
};

export const CAPABILITY_DEFAULTS = {
  artifact_type: 'none',
  registry: 'none',
  deploy_target: 'none'
};

// Execution phases. A phase is WHEN a run happens in the delivery lifecycle, not
// what the repository is.
//
//   pr        a pull request / scheduled sweep: source controls and the
//             pre-push image scan. Nothing is published and nothing is deployed.
//   delivery  a push to the release branch: everything in `pr`, plus registry
//             collection, the artifact gate, and the gated deploy.
export const PHASES = ['pr', 'delivery'];
export const DEFAULT_PHASE = 'pr';

const SOURCE_PHASES = ['pr', 'delivery'];
const DELIVERY_ONLY = ['delivery'];

// Controls the framework can perform.
//
// `appliesWhen` returns either true, or a STRING REASON explaining which
// declared capability removed the control's subject. The reason is the whole
// point: "N/A" with no reason is indistinguishable from an unexplained skip.
//
// `phases` lists the execution phases in which the control is EXPECTED to run.
// Outside those phases it is `deferred`, never `pass`.
//
// `kind` decides what a result MEANS, because two different questions hide
// behind "did it pass?":
//
//   scan      did the scanner execute and produce TRUSTWORTHY EVIDENCE? A scan
//             that finds vulnerabilities has succeeded. It fails only when no
//             trustworthy report exists (crash, cancellation, integrity failure).
//   gate      did that evidence SATISFY SECURITY POLICY? A blocking verdict is a
//             gate failure — never a scanner failure.
//   delivery  did the delivery step (collection, deploy) complete?
//   approval  is the approval channel in place?
//
// A finding is not a scanner failure, and a report must never say it is.
export const CONTROLS = [
  {
    id: 'secret-scan',
    name: 'Secret scanning (Gitleaks + TruffleHog)',
    kind: 'scan',
    phases: SOURCE_PHASES,
    appliesWhen: () => true
  },
  {
    id: 'dependency-scan',
    name: 'Dependency scanning (npm audit / pip-audit / OSV-Scanner)',
    kind: 'scan',
    phases: SOURCE_PHASES,
    appliesWhen: () => true
  },
  {
    id: 'sast',
    name: 'SAST (Semgrep)',
    kind: 'scan',
    phases: SOURCE_PHASES,
    appliesWhen: () => true
  },
  {
    id: 'source-gate',
    name: 'Source security gate',
    kind: 'gate',
    gateLabel: 'the source security policy gate',
    phases: SOURCE_PHASES,
    appliesWhen: () => true
  },
  {
    id: 'image-scan-prepush',
    name: 'Pre-push image scan (Trivy) and image gate',
    kind: 'gate',
    gateLabel: 'the pre-push image gate',
    // Runs on the PR too: the whole point is catching an image problem BEFORE
    // the image is pushed anywhere.
    phases: SOURCE_PHASES,
    appliesWhen: ({ artifact_type: artifactType }) =>
      artifactType === 'container' ||
      `artifact_type=${artifactType}: this repository ships no container image, so there is no image to scan before push.`
  },
  {
    id: 'registry-scan-collect',
    name: 'Registry scan collection (push, poll by digest, normalize)',
    kind: 'delivery',
    phases: DELIVERY_ONLY,
    appliesWhen: ({ artifact_type: artifactType, registry }) => {
      if (artifactType !== 'container') {
        return `artifact_type=${artifactType}: this repository ships no container image, so nothing is pushed to a registry.`;
      }
      if (registry === 'none') {
        return 'registry=none: this repository publishes its image outside the framework, so the framework collects no registry scan.';
      }
      return true;
    }
  },
  {
    id: 'artifact-gate',
    name: 'Artifact gate over the normalized registry report',
    kind: 'gate',
    gateLabel: 'the artifact gate',
    phases: DELIVERY_ONLY,
    appliesWhen: ({ artifact_type: artifactType, registry }) => {
      if (artifactType !== 'container') {
        return `artifact_type=${artifactType}: there is no registry artifact to gate.`;
      }
      if (registry === 'none') {
        return 'registry=none: no registry scan report is produced, so there is nothing for the artifact gate to evaluate.';
      }
      return true;
    }
  },
  {
    id: 'gated-deploy',
    name: 'Deploy gated on the artifact verdict',
    kind: 'delivery',
    phases: DELIVERY_ONLY,
    appliesWhen: ({ deploy_target: deployTarget }) => {
      if (deployTarget === 'self-managed') {
        return 'deploy_target=self-managed: this repository deploys through its own pipeline, which this framework does not gate.';
      }
      if (deployTarget === 'none') {
        return 'deploy_target=none: this repository deploys nothing.';
      }
      return true;
    }
  },
  {
    id: 'break-glass',
    name: 'Break-glass approval for an eligible BLOCK',
    kind: 'approval',
    phases: SOURCE_PHASES,
    appliesWhen: (_capabilities, { breakGlassEnabled }) =>
      breakGlassEnabled === true ||
      'break_glass_enabled=false: this repository has no approval channel configured, so an eligible BLOCK simply stays blocked.'
  }
];

// Capability combinations that contradict each other. Left unchecked, each would
// silently mark a real control not-applicable — the exact failure mode this
// whole mechanism exists to prevent — so they fail closed instead.
const COHERENCE_RULES = [
  {
    when: ({ artifact_type: a, registry: r }) => r !== 'none' && a !== 'container',
    message: (c) =>
      `registry=${c.registry} requires artifact_type=container, but artifact_type=${c.artifact_type}. ` +
      'A repository that ships no container image has nothing to push to a registry.'
  },
  {
    when: ({ artifact_type: a, deploy_target: d }) => d === 'framework-gated' && a !== 'container',
    message: (c) =>
      `deploy_target=framework-gated requires artifact_type=container, but artifact_type=${c.artifact_type}. ` +
      'The framework gates a deploy by pinning the scanned image digest; there is no such digest here.'
  },
  {
    when: ({ registry: r, deploy_target: d }) => d === 'framework-gated' && r === 'none',
    message: () =>
      'deploy_target=framework-gated requires a registry, but registry=none. The gated deploy pulls the ' +
      'exact digest the artifact gate approved, which only exists when the framework collected a registry scan.'
  }
];

// Validates and normalizes a declared capability set. Throws on anything
// unrecognized or self-contradictory; a conformance report built on an
// uninterpretable declaration would be worse than none.
export function resolveCapabilities(declared = {}) {
  const capabilities = { ...CAPABILITY_DEFAULTS };

  for (const [key, value] of Object.entries(declared)) {
    assert(
      Object.hasOwn(CAPABILITY_VALUES, key),
      `unknown capability '${key}'; expected one of ${Object.keys(CAPABILITY_VALUES).join(', ')}`
    );
    if (value === undefined || value === null || value === '') {
      continue;
    }
    assert(
      CAPABILITY_VALUES[key].includes(value),
      `capability ${key}='${value}' is not one of ${CAPABILITY_VALUES[key].join(' | ')}`
    );
    capabilities[key] = value;
  }

  for (const rule of COHERENCE_RULES) {
    assert(!rule.when(capabilities), rule.message(capabilities));
  }

  return capabilities;
}

// An unknown phase fails closed rather than defaulting: silently treating a
// typo as `pr` would defer every delivery control and report a green run.
export function resolvePhase(value) {
  if (value === undefined || value === null || value === '') {
    return DEFAULT_PHASE;
  }
  assert(PHASES.includes(value), `phase '${value}' is not one of ${PHASES.join(' | ')}`);
  return value;
}

// An exemption is debt with an owner and a deadline. A missing field makes it
// unusable ON PURPOSE: an exemption nobody owns, or one that never expires, is
// how a temporary decision becomes permanent silently.
function validateExemption(entry, index) {
  assert(entry && typeof entry === 'object', `exemption[${index}] is not an object`);
  for (const field of ['control', 'reason', 'owner', 'expires']) {
    assert(
      typeof entry[field] === 'string' && entry[field].trim() !== '',
      `exemption[${index}] is missing '${field}'; an exemption needs a control, a reason, an owner, and an expiry`
    );
  }
  assert(
    CONTROLS.some((control) => control.id === entry.control),
    `exemption[${index}] names unknown control '${entry.control}'`
  );
  const expires = Date.parse(entry.expires);
  assert(
    Number.isFinite(expires),
    `exemption[${index}] has an unparseable expires '${entry.expires}'; use an ISO date (YYYY-MM-DD)`
  );
  return { ...entry, expiresAt: expires };
}

export async function loadExemptions(path) {
  if (!path) {
    return [];
  }
  let raw;
  try {
    raw = await readFile(resolve(path), 'utf8');
  } catch {
    // A consumer with no exemptions file has no exemptions. That is the normal
    // case and the safe one — it grants nothing.
    return [];
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`exemptions file ${path} is not valid JSON: ${error.message}`, { cause: error });
  }
  const entries = Array.isArray(parsed) ? parsed : parsed?.exemptions;
  assert(
    Array.isArray(entries),
    `exemptions file ${path} must be a JSON array, or an object with an 'exemptions' array`
  );
  return entries.map(validateExemption);
}

const PASSED_STATUSES = new Set(['pass', 'passed', 'success', 'applied']);
const BLOCKING_VERDICTS = new Set(['BLOCK', 'BLOCK_DEPLOY']);

function text(value) {
  return typeof value === 'string' ? value.trim() : value === undefined || value === null ? '' : String(value).trim();
}

// Turns one observed result into { passed, reason?, detail? } with a reason a
// newcomer can read and that states only what the evidence supports.
//
// Optional evidence a caller may add beside `status` for a gate control:
//   verdict            the gate's verdict output (PASS, BLOCK, BLOCK_DEPLOY, ...)
//   gate_mode          the mode the gate actually ran in (echoed output)
//   integrity_trusted  'false' when a scan report could not be interpreted
// Without them the reason says only what the status proves.
export function explainObserved(control, result) {
  const status = text(result?.status).toLowerCase();
  const verdict = text(result?.verdict).toUpperCase();
  const mode = text(result?.gate_mode ?? result?.gateMode).toLowerCase();
  const trusted = text(result?.integrity_trusted ?? result?.integrityTrusted).toLowerCase();
  const kind = control.kind ?? 'other';
  const gateLabel = control.gateLabel ?? 'the gate';

  if (PASSED_STATUSES.has(status)) {
    if (kind === 'scan') {
      return {
        passed: true,
        detail:
          'scanner executed and produced trustworthy evidence; any findings are judged by the policy gate, not counted as a scanner failure'
      };
    }
    if (kind === 'gate' && verdict !== '') {
      if (BLOCKING_VERDICTS.has(verdict)) {
        const suppressed =
          mode === 'log-only'
            ? `verdict ${verdict} reported but NOT enforced (gate_mode=log-only)`
            : `verdict ${verdict} did not fail the gate job (gate_mode=${mode || 'unknown'}); only a verified break-glass approval permits that in enforce mode`;
        return {
          passed: true,
          detail: trusted === 'false' ? `${suppressed}; a scan report could not be trusted, so results are UNKNOWN` : suppressed
        };
      }
      return {
        passed: true,
        detail: `policy verdict ${verdict}${mode === 'log-only' ? ' (gate_mode=log-only; no blocking verdict to suppress)' : ''}`
      };
    }
    return { passed: true };
  }

  if (status === '') {
    return {
      passed: false,
      reason: 'no result was supplied (empty status); absence of evidence is not evidence the control ran'
    };
  }
  if (status === 'skipped') {
    return { passed: false, reason: 'the job was skipped, so the control did not execute' };
  }
  if (status === 'cancelled') {
    return {
      passed: false,
      reason:
        kind === 'scan'
          ? 'the scanner job was cancelled before producing a trustworthy report; findings are UNKNOWN, not clean'
          : 'the job was cancelled before the control completed'
    };
  }

  if (kind === 'scan') {
    if (status === 'untrusted') {
      return {
        passed: false,
        reason:
          'the scanner job completed, but the security gate could not interpret its report (report-integrity failure); findings are UNKNOWN, not clean'
      };
    }
    if (['failure', 'fail', 'failed'].includes(status)) {
      return {
        passed: false,
        reason:
          'the scanner job failed, so no trustworthy report was produced; findings are UNKNOWN, not clean. (Findings alone never fail a scanning control.)'
      };
    }
  }

  if (kind === 'gate' && ['failure', 'fail', 'failed'].includes(status)) {
    if (BLOCKING_VERDICTS.has(verdict) && trusted === 'false') {
      return {
        passed: false,
        reason: `${gateLabel} failed closed: a scan report could not be trusted (report-integrity failure), so the verdict is ${verdict}; results are UNKNOWN, not clean`
      };
    }
    if (BLOCKING_VERDICTS.has(verdict)) {
      return {
        passed: false,
        reason: `${gateLabel} returned a blocking result (verdict ${verdict}): the scan evidence did not satisfy security policy`
      };
    }
    if (verdict !== '') {
      return {
        passed: false,
        reason: `the gate job failed although its verdict was ${verdict}, so the gate did not complete; treated as failed (fail-closed)`
      };
    }
    return {
      passed: false,
      reason: 'the gate job failed; no verdict was supplied to say whether policy blocked or the job errored'
    };
  }

  if (['failure', 'fail', 'failed'].includes(status)) {
    return { passed: false, reason: 'the job failed' };
  }
  return { passed: false, reason: `unrecognized result '${result?.status}'; treated as failed (fail-closed)` };
}

// ---- break-glass evidence ----------------------------------------------------
//
// Two modes, chosen EXPLICITLY by the caller (`strict_break_glass_evidence` on
// _conformance.yml -> `strictBreakGlassEvidence` here), never inferred from
// which fields an entry happens to carry — otherwise a producer could opt out
// of strict checking by omitting fields.
//
//   legacy (v1 default)  the break-glass entry is judged exactly as before
//                        this schema existed: by `status` alone, like any other
//                        control. A loud deprecation warning says the evidence
//                        proves no delivery, decision, delegation or digest.
//                        Source-gate `override` claims are IGNORED (they never
//                        had meaning in v1), so legacy mode gains nothing new.
//   strict (opt-in; unconditional in v2)
//                        the rules below.
//
// STRICT: with `break_glass_enabled=true` the control accepts ONLY structured
// evidence observed from `_break-glass-lambda.yml` and the source workflow. A
// bare `{"status": "pass"}` — the fabricated shape this schema exists to
// remove — fails, as does any entry missing a required field. (Other controls
// keep their v1 status-based handling in both modes.)
//
// Required fields on the `break-glass` entry (all present, even if empty):
//   status             the break-glass job's result (needs.<job>.result)
//   decision           its decision_status output ('' when the job did not run)
//   request_delivered  its request_delivered output
//   gate_digest        its gate_digest output
//   delegated          the SOURCE workflow's break_glass_delegated output
// and an observed `source-gate` entry (non-empty status).
//
// Exactly two shapes pass:
//   not exercised  delegated=false, status=skipped, decision ''/not-applicable,
//                  request_delivered ''/false, gate_digest '', no override
//                  claimed on source-gate, and the source gate did not report
//                  an eligible, trusted, enforced BLOCK
//   approved       delegated=true, status=success, request_delivered=true,
//                  decision=approved, a SHA-256 gate_digest equal to the
//                  source-gate gate_digest, and a source verdict BLOCK that was
//                  trusted, break-glass eligible and enforced
// Everything else — denied, expired, timeout, refused, error, cancelled,
// delegated-but-skipped, missing or inconsistent fields — fails.
const HEX64 = /^[0-9a-f]{64}$/;

export const BREAK_GLASS_EVIDENCE_FIELDS = ['status', 'decision', 'request_delivered', 'gate_digest', 'delegated'];

export function explainBreakGlass(result, sourceGate = null) {
  const missing = BREAK_GLASS_EVIDENCE_FIELDS.filter(
    (field) => !result || typeof result !== 'object' || !Object.hasOwn(result, field)
  );
  if (missing.length > 0) {
    return {
      passed: false,
      reason:
        `break-glass is enabled, so structured observed evidence is required; missing ${missing.join(', ')}. ` +
        'A status-only entry proves only that something reported success, not that a decision was observed.'
    };
  }
  if (!sourceGate || text(sourceGate.status) === '') {
    return { passed: false, reason: 'no source-gate result was observed, so the break-glass evidence cannot be judged against it' };
  }

  const status = text(result.status).toLowerCase();
  const decision = text(result.decision).toLowerCase();
  const delivered = text(result.request_delivered).toLowerCase();
  // Digests are compared exactly, as final-gate.mjs does: no case folding.
  const digest = text(result.gate_digest);
  const delegated = text(result.delegated).toLowerCase();
  const sg = {
    verdict: text(sourceGate.verdict).toUpperCase(),
    trusted: text(sourceGate.integrity_trusted).toLowerCase(),
    eligible: text(sourceGate.break_glass_eligible).toLowerCase(),
    mode: text(sourceGate.gate_mode).toLowerCase(),
    digest: text(sourceGate.gate_digest),
    override: text(sourceGate.override).toLowerCase()
  };

  if (delegated === 'false') {
    const notExercised = [
      [status === 'skipped', `the break-glass job result is '${status}', but nothing was delegated to it`],
      [['', 'not-applicable'].includes(decision), `a decision '${decision}' is reported although nothing was delegated`],
      [['', 'false'].includes(delivered), 'a delivered request is reported although nothing was delegated'],
      [digest === '', 'a gate digest is reported although nothing was delegated'],
      [sg.override === '', `the source gate claims override '${sg.override}' although no break-glass was exercised`],
      [
        !(sg.verdict === 'BLOCK' && sg.eligible === 'true' && sg.trusted === 'true' && sg.mode === 'enforce'),
        'the source gate reported an eligible enforced BLOCK, but it was not delegated to break-glass, so no approval was attempted'
      ]
    ];
    for (const [ok, reason] of notExercised) {
      if (!ok) return { passed: false, reason };
    }
    return {
      passed: true,
      exercised: false,
      detail: 'approval channel configured; not exercised in this run — the source gate produced no eligible enforced BLOCK, so no approval attempt was needed'
    };
  }

  if (delegated !== 'true') {
    return { passed: false, reason: `delegated is '${delegated}'; expected the source workflow's break_glass_delegated output (true | false)` };
  }
  if (status === 'skipped' || status === '') {
    return { passed: false, reason: 'an eligible BLOCK was delegated to break-glass, but the break-glass workflow did not run; no approval was requested' };
  }
  if (status === 'cancelled') {
    return { passed: false, reason: 'the break-glass job was cancelled before a verified decision existed' };
  }
  if (['denied', 'expired', 'timeout'].includes(decision)) {
    return {
      passed: false,
      reason: `approval channel ${delivered === 'true' ? 'executed and delivered the request' : 'executed'}, but the decision was ${decision}; nothing was approved and the BLOCK stands`
    };
  }
  if (decision === 'refused') {
    return { passed: false, reason: 'the break-glass workflow refused the evidence before any request (not an overridable BLOCK, or not bound to this run); nothing was approved' };
  }

  const approved = [
    [status === 'success', `the break-glass job result is '${status}'`],
    [decision === 'approved', `the break-glass decision is '${decision || 'none'}'`],
    [delivered === 'true', `request_delivered is '${delivered}'`],
    [HEX64.test(digest), 'the break-glass gate digest is missing or malformed'],
    [digest === sg.digest, 'the approval is bound to a different gate digest than the source gate'],
    [sg.verdict === 'BLOCK', `the source verdict is '${sg.verdict}', not BLOCK`],
    [sg.trusted === 'true', 'the source scans were not trusted (integrity), which is never overridable'],
    [sg.eligible === 'true', 'the source BLOCK is not break-glass eligible'],
    [sg.mode === 'enforce', `the source gate_mode is '${sg.mode}', not enforce`]
  ];
  for (const [ok, reason] of approved) {
    if (!ok) {
      return { passed: false, reason: `the approval channel did not produce a verified approval for this gate: ${reason} (fail-closed)` };
    }
  }
  return {
    passed: true,
    exercised: true,
    detail: `approval channel executed; request delivered; decision approved for gate sha256 ${digest}`
  };
}

// A source-gate `override` claim is only believed when the break-glass
// observation proves it. Returns { verified, reason }.
export function verifySourceOverride(sourceGate, breakGlass, breakGlassEnabled) {
  const fail = (reason) => ({
    verified: false,
    reason: `the source gate claims a break-glass override, but ${reason}; a claimed override without matching break-glass evidence is not an override`
  });
  if (breakGlassEnabled !== true) return fail('break_glass_enabled=false for this repository');
  if (!breakGlass) return fail('no break-glass observation was supplied');
  const sgDigest = text(sourceGate.gate_digest);
  const checks = [
    [text(sourceGate.verdict).toUpperCase() === 'BLOCK', `the source verdict is '${text(sourceGate.verdict)}', not BLOCK`],
    [text(sourceGate.gate_mode).toLowerCase() === 'enforce', `the source gate_mode is '${text(sourceGate.gate_mode)}', not enforce`],
    [text(sourceGate.integrity_trusted).toLowerCase() === 'true', 'the source scans were not trusted (integrity), which is never overridable'],
    [text(sourceGate.break_glass_eligible).toLowerCase() === 'true', 'the source BLOCK is not break-glass eligible'],
    [text(breakGlass.status).toLowerCase() === 'success', `the break-glass job result is '${text(breakGlass.status)}'`],
    [text(breakGlass.decision).toLowerCase() === 'approved', `the break-glass decision is '${text(breakGlass.decision)}'`],
    [text(breakGlass.request_delivered).toLowerCase() === 'true', 'no break-glass request was delivered'],
    [HEX64.test(sgDigest), 'the source gate digest is missing or malformed'],
    [text(breakGlass.gate_digest) === sgDigest, 'the approval is bound to a different gate digest']
  ];
  for (const [ok, reason] of checks) {
    if (!ok) return fail(reason);
  }
  return { verified: true, digest: sgDigest };
}

// Builds the conformance report.
//
// `observed` maps control id -> { status: 'pass'|'fail'|..., evidence: string },
// optionally with gate evidence (see explainObserved).
// A control that applies AND is expected in this phase but was never observed is
// `failed`: absence of evidence is not evidence the control ran.
export function buildConformance({
  capabilities,
  observed = {},
  exemptions = [],
  breakGlassEnabled = false,
  // Explicit, default false (v1 compatibility). See "break-glass evidence".
  strictBreakGlassEvidence = false,
  phase = DEFAULT_PHASE,
  now = Date.now(),
  repository = null
}) {
  const warnings = [];
  const controls = [];

  for (const control of CONTROLS) {
    const applicability = control.appliesWhen(capabilities, { breakGlassEnabled });
    const result = observed[control.id];
    const base = {
      id: control.id,
      name: control.name,
      kind: control.kind,
      phases: control.phases
    };

    if (applicability !== true) {
      // A control the capabilities say cannot exist, yet which produced a
      // result, means the declaration and the pipeline disagree. Report the
      // fact rather than quietly trusting either side.
      if (result) {
        warnings.push(
          `control '${control.id}' is not applicable (${applicability}) but reported a result ` +
            `('${result.status}'); the capability declaration and the caller workflow disagree.`
        );
      }
      controls.push({
        ...base,
        appliesToRepository: false,
        status: 'not-applicable',
        reason: applicability
      });
      continue;
    }

    // From here the control IS required of this repository. The only question
    // left is whether this particular run was supposed to execute it.
    if (!control.phases.includes(phase)) {
      // A PR claiming a deploy control passed is a fabricated result, and the
      // most likely way for one to appear is a caller hard-coding "pass".
      if (result) {
        warnings.push(
          `control '${control.id}' does not run in the '${phase}' phase but reported a result ` +
            `('${result.status}'); a control that did not execute cannot have passed.`
        );
      }
      controls.push({
        ...base,
        appliesToRepository: true,
        status: 'deferred',
        reason:
          `required by this repository, but runs in the ${control.phases.join('/')} phase; ` +
          `this run is the '${phase}' phase`
      });
      continue;
    }

    const exemption = exemptions.find((entry) => entry.control === control.id);
    if (exemption) {
      if (exemption.expiresAt < now) {
        // Expires CLOSED. An exemption past its date stops granting anything,
        // so forgetting to review it fails the build instead of extending it.
        warnings.push(
          `exemption for '${control.id}' expired on ${exemption.expires} and no longer applies.`
        );
      } else {
        controls.push({
          ...base,
          appliesToRepository: true,
          status: 'exempt',
          reason: exemption.reason,
          owner: exemption.owner,
          expires: exemption.expires
        });
        continue;
      }
    }

    if (!result) {
      controls.push({
        ...base,
        appliesToRepository: true,
        status: 'failed',
        reason: `the control applies and runs in the '${phase}' phase but reported no result`
      });
      continue;
    }

    let explained;
    const extra = {};
    if (control.id === 'break-glass' && strictBreakGlassEvidence === true) {
      // Only reached when break-glass is enabled (otherwise N/A above).
      explained = explainBreakGlass(result, observed['source-gate'] ?? null);
      extra.exercised = explained.exercised;
      if (text(result.decision) !== '') extra.decision = text(result.decision);
      if (text(result.request_delivered) !== '') extra.requestDelivered = text(result.request_delivered) === 'true';
    } else {
      explained = explainObserved(control, result);
      if (control.id === 'break-glass') {
        warnings.push(
          "DEPRECATED (v1 legacy break-glass evidence): control 'break-glass' was judged by its status alone " +
            `('${text(result.status)}'). That proves NOTHING about request delivery, the approval decision, ` +
            'delegation, or binding to a gate digest — it is not verified evidence. Set ' +
            'strict_break_glass_evidence: true and feed the structured fields from _break-glass-lambda.yml. ' +
            'Legacy mode is removed in v2.'
        );
      }
    }

    // A policy BLOCK stays a policy BLOCK. The source-gate control may read as
    // applied on a failed job ONLY when a verified approval for this exact gate
    // was observed, and the report says so explicitly.
    const override = text(result.override).toLowerCase();
    if (control.id === 'source-gate' && override !== '' && strictBreakGlassEvidence !== true) {
      // v1 never interpreted `override`; legacy mode must not start now.
      warnings.push(
        `control 'source-gate' claims override '${override}', which is IGNORED in legacy break-glass evidence mode: ` +
          'an override is only honoured when strict_break_glass_evidence is true and proven by the break-glass observation.'
      );
    }
    if (control.id === 'source-gate' && override === 'approved' && strictBreakGlassEvidence === true) {
      const verdict = verifySourceOverride(result, observed['break-glass'], breakGlassEnabled);
      if (verdict.verified) {
        explained = {
          passed: true,
          detail: `policy verdict BLOCK; override: verified approved break-glass for gate sha256 ${verdict.digest}`
        };
        extra.override = 'approved';
      } else {
        explained = { passed: false, reason: verdict.reason };
      }
    }

    controls.push({
      ...base,
      appliesToRepository: true,
      status: explained.passed ? 'applied' : 'failed',
      reason: explained.passed ? undefined : explained.reason,
      detail: explained.detail,
      observedStatus: text(result.status),
      ...(text(result.verdict) !== '' ? { verdict: text(result.verdict) } : {}),
      ...Object.fromEntries(Object.entries(extra).filter(([, value]) => value !== undefined)),
      evidence: result.evidence ?? undefined
    });
  }

  const count = (status) => controls.filter((control) => control.status === status).length;

  return {
    schemaVersion: 2,
    generatedAt: new Date(now).toISOString(),
    repository: repository ?? undefined,
    phase,
    capabilities,
    breakGlassEnabled,
    // Additive: which break-glass evidence rules this report applied.
    breakGlassEvidence: strictBreakGlassEvidence === true ? 'strict' : 'legacy',
    controls,
    warnings,
    summary: {
      // "Which required controls executed successfully in THIS run?"
      applied: count('applied'),
      deferred: count('deferred'),
      notApplicable: count('not-applicable'),
      exempt: count('exempt'),
      failed: count('failed'),
      // "What does this repository require, regardless of phase?"
      requiredByRepository: controls.filter((control) => control.appliesToRepository).length
    }
  };
}

export function renderMarkdown(report) {
  const symbol = {
    applied: '✅ applied',
    deferred: '⏳ deferred',
    'not-applicable': '➖ N/A',
    exempt: '⚠️ exempt',
    failed: '❌ failed'
  };
  const { summary } = report;
  const plural = (count, word) => `**${count}** ${word}${count === 1 ? '' : 's'}`;
  const lines = [
    '## Conformance',
    '',
    `Phase: \`${report.phase}\``,
    '',
    `Declared: \`artifact_type=${report.capabilities.artifact_type}\` ` +
      `\`registry=${report.capabilities.registry}\` ` +
      `\`deploy_target=${report.capabilities.deploy_target}\``,
    '',
    ...(report.breakGlassEnabled
      ? [
          report.breakGlassEvidence === 'strict'
            ? 'Break-glass evidence: **strict** (structured, observed decision required).'
            : '> ⚠️ Break-glass evidence: **legacy (deprecated)** — the break-glass control is judged by status alone, which proves no delivery, decision, delegation or digest binding. Set `strict_break_glass_evidence: true`; legacy mode is removed in v2.',
          ''
        ]
      : []),
    `This repository requires ${plural(summary.requiredByRepository, 'control')}. In this \`${report.phase}\` run: ` +
      `**${summary.applied}** applied (executed successfully), ` +
      `**${summary.failed}** failed, ` +
      `**${summary.deferred}** deferred to another phase, ` +
      `**${summary.exempt}** exempt. ` +
      `${plural(summary.notApplicable, 'control')} ${summary.notApplicable === 1 ? 'is' : 'are'} not applicable to this repository.`,
    '',
    '> **Scanning controls** answer *did the scanner execute and produce trustworthy evidence?* ' +
      'A scanner that finds vulnerabilities has still been applied. **Gate controls** answer ' +
      '*did that evidence satisfy security policy?* A finding is not a scanner failure.',
    '',
    '| Control | Status | Why |',
    '| --- | --- | --- |'
  ];
  for (const control of report.controls) {
    const why =
      control.status === 'exempt'
        ? `${control.reason} — owner ${control.owner}, expires ${control.expires}`
        : (control.reason ?? control.detail ?? '');
    lines.push(`| ${control.name} | ${symbol[control.status]} | ${why} |`);
  }
  if (report.warnings.length > 0) {
    lines.push('', '**Warnings**', '');
    for (const warning of report.warnings) {
      lines.push(`- ${warning}`);
    }
  }
  return lines.join('\n');
}

function parseArguments(argv) {
  const options = {
    capabilities: {},
    observed: {},
    exemptions: null,
    output: 'reports/conformance.json',
    breakGlassEnabled: false,
    strictBreakGlassEvidence: false,
    phase: DEFAULT_PHASE,
    repository: null
  };

  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    assert(value !== undefined, `missing value for ${flag}`);
    switch (flag) {
      case '--artifact-type':
        options.capabilities.artifact_type = value;
        break;
      case '--registry':
        options.capabilities.registry = value;
        break;
      case '--deploy-target':
        options.capabilities.deploy_target = value;
        break;
      case '--break-glass':
        options.breakGlassEnabled = value === 'true';
        break;
      case '--strict-break-glass-evidence':
        // Fail closed on anything but an explicit boolean: a typo must not
        // silently select either mode.
        assert(value === 'true' || value === 'false', `--strict-break-glass-evidence must be true or false, got '${value}'`);
        options.strictBreakGlassEvidence = value === 'true';
        break;
      case '--phase':
        options.phase = value;
        break;
      case '--exemptions':
        options.exemptions = value;
        break;
      case '--observed':
        options.observed = JSON.parse(value);
        break;
      case '--repository':
        options.repository = value;
        break;
      case '--output':
        options.output = value;
        break;
      default:
        throw new Error(`unknown argument ${flag}`);
    }
  }

  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const capabilities = resolveCapabilities(options.capabilities);
  const phase = resolvePhase(options.phase);
  const exemptions = await loadExemptions(options.exemptions);

  const report = buildConformance({
    capabilities,
    observed: options.observed,
    exemptions,
    breakGlassEnabled: options.breakGlassEnabled,
    strictBreakGlassEvidence: options.strictBreakGlassEvidence,
    phase,
    repository: options.repository
  });

  const outputPath = resolve(options.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);

  console.log(renderMarkdown(report));

  // A failed control fails this script. N/A, deferred, and a live exemption do
  // not — that is the entire set of distinctions this report exists to make.
  if (report.summary.failed > 0) {
    console.error(`\n${report.summary.failed} applicable control(s) did not pass.`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
