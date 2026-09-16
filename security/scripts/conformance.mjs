// Capability-aware conformance reporting.
//
// Consumer repositories differ in what they SHIP, not just in how they are
// configured. A library has no container to scan; a repo with its own delivery
// pipeline has no framework-gated deploy. Reporting those controls as "skipped"
// makes a conformance report useless, because it cannot be distinguished from a
// control that was switched off.
//
// So every control resolves to exactly one of:
//
//   applied         the control ran, and its observed result is recorded
//   not-applicable  the repo's declared capabilities mean the control has no
//                   subject. A STABLE FACT about what this repo is. Carries a
//                   reason naming the capability that made it so.
//   exempt          the control applies and is deliberately not being enforced.
//                   DEBT: carries an owner and an expiry, and expires closed.
//   failed          the control applies, is not exempt, and did not pass.
//
// `not-applicable` and `exempt` are deliberately different words for deliberately
// different things. A library will never grow an image to scan; a repo that
// exempted its image gate is carrying risk someone agreed to revisit. A report
// that renders both as "skipped" tells a reviewer nothing.
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

// Controls the framework can perform, and the capability predicate that decides
// whether each has a subject in this repository.
//
// `appliesWhen` returns either true, or a STRING REASON explaining which
// declared capability removed the control's subject. The reason is the whole
// point: "N/A" with no reason is indistinguishable from an unexplained skip.
export const CONTROLS = [
  {
    id: 'secret-scan',
    name: 'Secret scanning (Gitleaks + TruffleHog)',
    appliesWhen: () => true
  },
  {
    id: 'dependency-scan',
    name: 'Dependency scanning (npm audit / pip-audit / OSV-Scanner)',
    appliesWhen: () => true
  },
  {
    id: 'sast',
    name: 'SAST (Semgrep)',
    appliesWhen: () => true
  },
  {
    id: 'source-gate',
    name: 'Source security gate',
    appliesWhen: () => true
  },
  {
    id: 'image-scan-prepush',
    name: 'Pre-push image scan (Trivy) and image gate',
    appliesWhen: ({ artifact_type: artifactType }) =>
      artifactType === 'container' ||
      `artifact_type=${artifactType}: this repository ships no container image, so there is no image to scan before push.`
  },
  {
    id: 'registry-scan-collect',
    name: 'Registry scan collection (push, poll by digest, normalize)',
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
    throw new Error(`exemptions file ${path} is not valid JSON: ${error.message}`);
  }
  const entries = Array.isArray(parsed) ? parsed : parsed?.exemptions;
  assert(
    Array.isArray(entries),
    `exemptions file ${path} must be a JSON array, or an object with an 'exemptions' array`
  );
  return entries.map(validateExemption);
}

// Builds the conformance report.
//
// `observed` maps control id -> { status: 'pass'|'fail'|..., evidence: string }.
// A control that applies but was never observed is `failed`, not `applied`:
// absence of evidence is not evidence the control ran.
export function buildConformance({
  capabilities,
  observed = {},
  exemptions = [],
  breakGlassEnabled = false,
  now = Date.now(),
  repository = null
}) {
  const warnings = [];
  const controls = [];

  for (const control of CONTROLS) {
    const applicability = control.appliesWhen(capabilities, { breakGlassEnabled });
    const result = observed[control.id];

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
        id: control.id,
        name: control.name,
        status: 'not-applicable',
        reason: applicability
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
          id: control.id,
          name: control.name,
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
        id: control.id,
        name: control.name,
        status: 'failed',
        reason: 'the control applies to this repository but reported no result'
      });
      continue;
    }

    const passed = ['pass', 'passed', 'success', 'applied'].includes(
      String(result.status).toLowerCase()
    );
    controls.push({
      id: control.id,
      name: control.name,
      status: passed ? 'applied' : 'failed',
      reason: passed ? undefined : `observed result '${result.status}'`,
      evidence: result.evidence ?? undefined
    });
  }

  const count = (status) => controls.filter((control) => control.status === status).length;

  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    repository: repository ?? undefined,
    capabilities,
    breakGlassEnabled,
    controls,
    warnings,
    summary: {
      applied: count('applied'),
      notApplicable: count('not-applicable'),
      exempt: count('exempt'),
      failed: count('failed')
    }
  };
}

export function renderMarkdown(report) {
  const symbol = {
    applied: '✅ applied',
    'not-applicable': '➖ N/A',
    exempt: '⚠️ exempt',
    failed: '❌ failed'
  };
  const lines = [
    '## Conformance',
    '',
    `Declared: \`artifact_type=${report.capabilities.artifact_type}\` ` +
      `\`registry=${report.capabilities.registry}\` ` +
      `\`deploy_target=${report.capabilities.deploy_target}\``,
    '',
    '| Control | Status | Why |',
    '| --- | --- | --- |'
  ];
  for (const control of report.controls) {
    const why =
      control.status === 'exempt'
        ? `${control.reason} — owner ${control.owner}, expires ${control.expires}`
        : (control.reason ?? '');
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
  const exemptions = await loadExemptions(options.exemptions);

  const report = buildConformance({
    capabilities,
    observed: options.observed,
    exemptions,
    breakGlassEnabled: options.breakGlassEnabled,
    repository: options.repository
  });

  const outputPath = resolve(options.output);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);

  console.log(renderMarkdown(report));

  // A failed control fails this script. N/A and a live exemption do not — that
  // is the entire distinction this report exists to make.
  if (report.summary.failed > 0) {
    console.error(`\n${report.summary.failed} applicable control(s) did not pass.`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
