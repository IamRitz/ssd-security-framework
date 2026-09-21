// Rendering: config -> generated files. A PURE function of the config: it reads
// nothing from the repository and embeds no timestamp, so identical config and
// framework version always produce byte-identical output.
import { CAPABILITIES_BY_PROFILE, isContainerProfile, isEcrProfile } from './config.mjs';
import { withMarker } from './files.mjs';
import { ACTIONS, IMAGE_TARBALL, NODE_VERSION, imageArtifact } from './pins.mjs';
import { formatScalar as q } from './yaml.mjs';

const reusable = (config, file) => `${config.framework.repository}/.github/workflows/${file}@${config.framework.ref}`;

// `bootstrap_baseline` exists only while no baseline has been accepted. It is a
// workflow_dispatch checkbox rather than a repository variable: a dispatched run
// performs a FULL Semgrep scan (a pull_request run is diff-aware and would
// produce a baseline missing the existing backlog), and nothing lingers after.
export const bootstrapAvailable = (config) =>
  config.semgrep.baseline.state === 'absent' && config.rollout.gateMode === 'log-only';

function block(lines, indent, text) {
  const pad = ' '.repeat(indent);
  for (const line of text.split('\n')) {
    lines.push(line === '' ? '' : `${pad}${line}`);
  }
}

function toolkitInputs(config) {
  return [
    `toolkit_repository: ${q(config.framework.repository)}`,
    `# MUST equal the @ref of the uses: line above (a reusable workflow cannot read its own ref).`,
    `toolkit_ref: ${q(config.framework.ref)}`
  ];
}

function slackSecret(lines, config, indent) {
  if (!config.notifications.slack.enabled) {
    return;
  }
  block(
    lines,
    indent,
    [
      '# The webhook URL is a credential, so it travels as a declared SECRET that the',
      "# reusable workflow hands to its notifier step only — never `secrets: inherit`.",
      'secrets:',
      `  slack_notify_webhook: \${{ secrets.${config.notifications.slack.githubSecretName} }}`
    ].join('\n')
  );
}

function sourceSecurityJob(config, { phase }) {
  const lines = [];
  const gateMode = phase === 'delivery' ? 'enforce' : config.rollout.gateMode;
  lines.push('  source-security:');
  if (phase === 'delivery') {
    block(lines, 4, '# Re-run on the delivery commit rather than trusting the PR result: what\n# merged may not be what was reviewed.');
  }
  block(
    lines,
    4,
    [
      '# `_source-scan.yml` is the OIDC-free source workflow: no job in it can request a',
      '# GitHub OIDC token, so this caller grants none.',
      '# NEVER `secrets: inherit` — that would hand every repository secret to the scanners.',
      `uses: ${reusable(config, '_source-scan.yml')}`
    ].join('\n')
  );
  block(
    lines,
    4,
    [
      'permissions:',
      '  contents: read',
      '  pull-requests: write'
    ].join('\n')
  );
  slackSecret(lines, config, 4);
  lines.push('    with:');
  block(lines, 6, toolkitInputs(config).join('\n'));
  if (phase === 'delivery') {
    block(lines, 6, '# Delivery never runs log-only: a non-enforcing delivery would push and deploy\n# an image whose gates were not enforced.');
  }
  lines.push(`      gate_mode: ${gateMode}`);
  if (phase === 'pr' && bootstrapAvailable(config)) {
    block(
      lines,
      6,
      [
        '# ONE-TIME onboarding, dispatch only (see `ssd-onboard baseline prepare`). Removed',
        '# from this file when the baseline is accepted.',
        "bootstrap_baseline: ${{ github.event_name == 'workflow_dispatch' && inputs.bootstrap_baseline == true }}"
      ].join('\n')
    );
  }
  lines.push('      semgrep_configs: |');
  block(lines, 8, config.semgrep.rulesets.join('\n'));
  lines.push(`      semgrep_paths: ${q(config.semgrep.roots.join(' '))}`);
  lines.push(`      semgrep_baseline_path: ${q(config.semgrep.baseline.path)}`);
  const gitleaksConfig = config.gitleaks.mode === 'default' ? '' : config.gitleaks.path;
  block(
    lines,
    6,
    [
      '# Explicit, including when empty: an empty value means "no file", so a stray',
      "# config added later in some PR cannot silently change what is scanned.",
      `gitleaks_config: ${q(gitleaksConfig)}`,
      `trufflehog_exclude_paths: ${q(config.trufflehog.excludePathsFile)}`
    ].join('\n')
  );
  // Break-glass is not generated in Phase 1 (config accepts only `disabled`).
  lines.push('      break_glass_enabled: false');
  return lines;
}

function containerBuildJob(config, { phase }) {
  const c = config.container;
  const lines = ['  container-build:', '    name: Container build'];
  if (phase === 'pr') {
    lines.push("    if: github.event_name != 'schedule'");
  }
  block(
    lines,
    4,
    [
      '# ZERO cloud credentials and NO build arguments: `npm ci` / `pip install` run',
      "# other people's code here, and a build argument is baked into image history.",
      'runs-on: ubuntu-latest',
      'permissions:',
      '  contents: read',
      'steps:',
      '  - name: Check out the repository',
      `    uses: ${ACTIONS.checkout}`,
      '    with:',
      '      persist-credentials: false',
      '  - name: Set up Buildx',
      `    uses: ${ACTIONS.setupBuildx}`,
      `  - name: ${phase === 'delivery' ? 'Build the image that will actually ship' : 'Build without cloud credentials'}`,
      `    uses: ${ACTIONS.buildPush}`,
      '    with:',
      `      context: ${q(c.context === '.' ? '.' : `./${c.context}`)}`,
      `      file: ${q(`./${c.dockerfile}`)}`,
      '      load: true',
      ...(phase === 'delivery'
        ? ['      # A poisoned Actions cache entry must never be baked into the image that ships.', '      no-cache: true']
        : []),
      `      tags: ${c.imageName}:\${{ github.sha }}`,
      ...(phase === 'pr' ? ['      cache-from: type=gha', '      cache-to: type=gha,mode=max'] : []),
      '  - name: Export image tarball',
      `    run: docker save -o ${IMAGE_TARBALL} "${c.imageName}:$GITHUB_SHA"`,
      '  - name: Upload image tarball',
      `    uses: ${ACTIONS.uploadArtifact}`,
      '    with:',
      `      name: ${imageArtifact()}`,
      `      path: ${IMAGE_TARBALL}`,
      '      if-no-files-found: error',
      '      retention-days: 1'
    ].join('\n')
  );
  return lines;
}

function imageSecurityJob(config, { phase }) {
  const lines = ['  image-security:'];
  block(
    lines,
    4,
    [
      '# Pre-push Trivy gate over the tarball. Assumes no cloud role and touches no registry.',
      'needs: container-build',
      ...(phase === 'pr' ? ["if: github.event_name != 'schedule'"] : []),
      `uses: ${reusable(config, '_image-scan-prepush.yml')}`,
      'permissions:',
      '  contents: read',
      '  pull-requests: write'
    ].join('\n')
  );
  slackSecret(lines, config, 4);
  lines.push('    with:');
  block(lines, 6, toolkitInputs(config).join('\n'));
  lines.push(`      image_artifact: ${imageArtifact()}`);
  lines.push(`      gate_mode: ${phase === 'delivery' ? 'enforce' : config.rollout.gateMode}`);
  return lines;
}

const LOG_ONLY_REPORTER = `report_log_only() {
  local control="$1" mode="$2" verdict="$3" blocking="$4"
  [ "$mode" = "log-only" ] || return 0
  if [ "$verdict" = "$blocking" ]; then
    echo "::warning::GREEN BY CONFIGURATION, not by verdict — $control verdict $verdict is reported but NOT enforced because gate_mode is log-only."
  elif [ -n "$verdict" ]; then
    echo "::warning::$control verdict $verdict. gate_mode is log-only; no blocking verdict exists, so nothing was suppressed. A future $blocking would not fail this check until the repository moves to enforce."
  else
    echo "::warning::$control verdict is unavailable, and gate_mode is log-only so nothing is enforced. Treat it as UNKNOWN, not clean."
  fi
}`;

function securityGateJob(config) {
  const container = isContainerProfile(config.profile);
  const lines = ['  security-gate:'];
  block(
    lines,
    4,
    [
      '# THE stable required check for branch protection. The name is a CONSTANT:',
      '# branch protection matches by exact string, so a computed name would stop',
      '# matching in one mode and the rule would silently protect nothing.',
      container
        ? '# A container PR is gated on source security AND the pre-push image gate.'
        : '# This repository ships no container, so source security is the whole PR contract.',
      'name: security-gate',
      ...(container ? ['needs:', '  - source-security', '  - image-security'] : ['needs: source-security']),
      '# always(): the required check must still report when a dependency fails.',
      'if: ${{ always() }}',
      'runs-on: ubuntu-latest',
      'permissions: {}',
      'steps:',
      '  - name: Require every security control that gates this pull request',
      '    env:',
      '      EVENT: ${{ github.event_name }}',
      '      SOURCE_RESULT: ${{ needs.source-security.result }}',
      '      SOURCE_VERDICT: ${{ needs.source-security.outputs.verdict }}',
      '      SOURCE_MODE: ${{ needs.source-security.outputs.gate_mode }}',
      ...(container
        ? [
            '      IMAGE_RESULT: ${{ needs.image-security.result }}',
            '      IMAGE_VERDICT: ${{ needs.image-security.outputs.verdict }}',
            '      IMAGE_MODE: ${{ needs.image-security.outputs.gate_mode }}'
          ]
        : []),
      '    run: |'
    ].join('\n')
  );
  const script = [
    'set -euo pipefail',
    'echo "event=$EVENT source=$SOURCE_RESULT verdict=${SOURCE_VERDICT:-unknown}"',
    'failed=0',
    'if [ "$SOURCE_RESULT" != "success" ]; then',
    '  echo "::error::source security did not pass (result=$SOURCE_RESULT)"',
    '  failed=1',
    'fi'
  ];
  if (container) {
    script.push(
      '# The scheduled sweep builds no image, so `skipped` is legitimate THERE and',
      '# only there. On any other event a skipped image gate is a missing control.',
      'if [ "$EVENT" = "schedule" ]; then',
      '  case "$IMAGE_RESULT" in',
      '    success|skipped) ;;',
      '    *)',
      '      echo "::error::image security did not pass (result=$IMAGE_RESULT)"',
      '      failed=1',
      '      ;;',
      '  esac',
      'elif [ "$IMAGE_RESULT" != "success" ]; then',
      '  echo "::error::image security did not pass (result=$IMAGE_RESULT); a container PR is gated on it"',
      '  failed=1',
      'fi'
    );
  }
  script.push(LOG_ONLY_REPORTER, 'report_log_only "source" "$SOURCE_MODE" "$SOURCE_VERDICT" BLOCK');
  if (container) {
    script.push('if [ "$IMAGE_RESULT" != "skipped" ]; then', '  report_log_only "image" "$IMAGE_MODE" "$IMAGE_VERDICT" BLOCK_DEPLOY', 'fi');
  }
  script.push('if [ "$failed" -ne 0 ]; then', '  exit 1', 'fi', 'echo "All pull-request security controls passed."');
  block(lines, 10, script.join('\n'));
  return lines;
}

function gateModeJob(config) {
  const container = isContainerProfile(config.profile);
  const lines = ['  gate-mode:'];
  block(
    lines,
    4,
    [
      '# Mode visibility as its own, deliberately NON-required check whose name carries',
      '# the mode the reusable workflow ACTUALLY evaluated under. It goes red (without',
      '# blocking the merge) whenever log-only is suppressing a BLOCK or a scan could',
      '# not be trusted.',
      `name: "\${{ needs.source-security.outputs.gate_mode == 'log-only' && 'gate-mode: LOG-ONLY (gate NOT enforcing)' || format('gate-mode: {0}', needs.source-security.outputs.gate_mode || 'unknown') }}"`,
      ...(container ? ['needs:', '  - source-security', '  - image-security'] : ['needs: source-security']),
      'if: ${{ always() }}',
      'runs-on: ubuntu-latest',
      'permissions: {}',
      'steps:',
      '  - name: Report the effective gate mode',
      '    env:',
      '      MODE: ${{ needs.source-security.outputs.gate_mode }}',
      '      SOURCE_VERDICT: ${{ needs.source-security.outputs.verdict }}',
      '      SOURCE_TRUSTED: ${{ needs.source-security.outputs.integrity_trusted }}',
      ...(container
        ? [
            '      IMAGE_RESULT: ${{ needs.image-security.result }}',
            '      IMAGE_VERDICT: ${{ needs.image-security.outputs.verdict }}',
            '      IMAGE_TRUSTED: ${{ needs.image-security.outputs.integrity_trusted }}'
          ]
        : []),
      '    run: |'
    ].join('\n')
  );
  const script = [
    '{',
    '  echo "## Gate mode: \\`${MODE:-unknown}\\`"',
    '  echo',
    '  echo "| | verdict | scan trusted |"',
    '  echo "| --- | --- | --- |"',
    '  echo "| source security | \\`${SOURCE_VERDICT:-unknown}\\` | \\`${SOURCE_TRUSTED:-unknown}\\` |"'
  ];
  if (container) {
    script.push(
      '  if [ "$IMAGE_RESULT" = "skipped" ]; then',
      '    echo "| pre-push image | _not run_ | _n/a_ |"',
      '  else',
      '    echo "| pre-push image | \\`${IMAGE_VERDICT:-unknown}\\` | \\`${IMAGE_TRUSTED:-unknown}\\` |"',
      '  fi'
    );
  }
  script.push(
    '} >> "$GITHUB_STEP_SUMMARY"',
    'suppressed=""',
    'if [ "$SOURCE_TRUSTED" != "true" ]; then',
    '  suppressed="$suppressed source-scan-not-trusted"',
    'fi'
  );
  if (container) {
    script.push(
      'if [ "$IMAGE_RESULT" != "skipped" ] && [ "$IMAGE_TRUSTED" != "true" ]; then',
      '  suppressed="$suppressed image-scan-not-trusted"',
      'fi'
    );
  }
  script.push(
    'if [ "$MODE" = "log-only" ]; then',
    '  echo "::warning::gate_mode is log-only — the required security-gate check cannot fail on findings in this repository."',
    '  if [ "$SOURCE_VERDICT" = "BLOCK" ]; then',
    '    suppressed="$suppressed source-BLOCK-suppressed"',
    '  fi'
  );
  if (container) {
    script.push('  if [ "$IMAGE_VERDICT" = "BLOCK_DEPLOY" ]; then', '    suppressed="$suppressed image-BLOCK_DEPLOY-suppressed"', '  fi');
  }
  script.push(
    'fi',
    'if [ -n "$suppressed" ]; then',
    '  echo "::error::Findings are not being enforced or not trustworthy:$suppressed"',
    '  exit 1',
    'fi',
    'echo "Gate mode ${MODE:-unknown}: nothing suppressed, scans trusted."'
  );
  block(lines, 10, script.join('\n'));
  return lines;
}

function observedSource() {
  return [
    '{"secret-scan":{"status":"${{ needs.source-security.outputs.secret_scan_result }}","evidence":"Secret scanning job (per-control output)"},',
    '"dependency-scan":{"status":"${{ needs.source-security.outputs.dependency_scan_result }}","evidence":"Dependency scanning job (per-control output)"},',
    '"sast":{"status":"${{ needs.source-security.outputs.sast_result }}","evidence":"SAST job (per-control output)"},',
    '"source-gate":{"status":"${{ needs.source-security.outputs.source_gate_result }}","verdict":"${{ needs.source-security.outputs.verdict }}","gate_mode":"${{ needs.source-security.outputs.gate_mode }}","integrity_trusted":"${{ needs.source-security.outputs.integrity_trusted }}","evidence":"source-gate job"}'
  ];
}

function conformanceJob(config, { phase }) {
  const container = isContainerProfile(config.profile);
  const capabilities = CAPABILITIES_BY_PROFILE[config.profile];
  const needs = ['source-security'];
  if (container) {
    needs.push('image-security');
  }
  if (phase === 'delivery') {
    needs.push('ecr-collect', 'artifact-gate', 'deploy');
  }
  let condition = 'always()';
  if (phase === 'delivery') {
    condition = `always() && github.ref == 'refs/heads/${config.repository.defaultBranch}'`;
  } else if (container) {
    condition = "always() && github.event_name != 'schedule'";
  }
  const observed = observedSource();
  if (container) {
    observed.push(
      '"image-scan-prepush":{"status":"${{ needs.image-security.result }}","verdict":"${{ needs.image-security.outputs.verdict }}","gate_mode":"${{ needs.image-security.outputs.gate_mode }}","integrity_trusted":"${{ needs.image-security.outputs.integrity_trusted }}","evidence":"pre-push Trivy gate"}'
    );
  }
  if (phase === 'delivery') {
    observed.push(
      '"registry-scan-collect":{"status":"${{ needs.ecr-collect.result }}","evidence":"ECR push + scan polled by digest"}',
      '"artifact-gate":{"status":"${{ needs.artifact-gate.result }}","verdict":"${{ needs.artifact-gate.outputs.verdict }}","evidence":"normalized report gated at the pushed digest"}',
      '"gated-deploy":{"status":"${{ needs.deploy.result }}","evidence":"SSM deploy pinned to the gated digest"}'
    );
  }
  for (let index = 0; index < observed.length - 1; index += 1) {
    if (!observed[index].endsWith(',')) {
      observed[index] += ',';
    }
  }
  observed[observed.length - 1] = observed[observed.length - 1].replace(/,$/, '') + '}';
  const lines = ['  conformance:'];
  block(
    lines,
    4,
    [
      phase === 'delivery'
        ? '# The DELIVERY-phase report: proves registry collection, the artifact gate and the deploy.'
        : '# Which controls this repository requires, and what happened to each in this run.',
      ...(needs.length === 1 ? ['needs: source-security'] : ['needs:', ...needs.map((job) => `  - ${job}`)]),
      `if: \${{ ${condition} }}`,
      `uses: ${reusable(config, '_conformance.yml')}`,
      'permissions:',
      '  contents: read',
      'with:'
    ].join('\n')
  );
  block(lines, 6, toolkitInputs(config).join('\n'));
  lines.push(`      phase: ${phase}`);
  lines.push(`      artifact_type: ${capabilities.artifact_type}`);
  lines.push(`      registry: ${capabilities.registry}`);
  lines.push(`      deploy_target: ${capabilities.deploy_target}`);
  lines.push('      break_glass_enabled: false');
  block(
    lines,
    6,
    '# PER-CONTROL evidence, never the aggregate `needs.source-security.result`: a policy\n# BLOCK would otherwise report three working scanners as failed.\nobserved: >-'
  );
  block(lines, 8, observed.join('\n'));
  return lines;
}

function header(config, lines, description) {
  const bootstrap = bootstrapAvailable(config);
  block(
    lines,
    0,
    [
      '#',
      ...description.map((line) => `# ${line}`),
      '#',
      `# Profile:    ${config.profile}`,
      `# Framework:  ${config.framework.repository}@${config.framework.ref}`,
      `# Gate mode:  ${config.rollout.gateMode}`,
      `# Baseline:   ${config.semgrep.baseline.path} (${config.semgrep.baseline.state})${bootstrap ? ' — bootstrap available via workflow_dispatch' : ''}`,
      '#',
      '# SECURITY: `pull_request`, never `pull_request_target`; no `secrets: inherit`.'
    ].join('\n')
  );
}

export function renderSecurityWorkflow(config) {
  const container = isContainerProfile(config.profile);
  const lines = [];
  header(config, lines, [
    `PR phase for ${config.repository.slug}: ${container ? 'source security, credential-free container build, pre-push Trivy' : 'source security'}.`,
    isEcrProfile(config.profile)
      ? `The delivery phase (push, registry scan, gated deploy) is ${config.workflows.delivery}.`
      : container
        ? 'This repository deploys through its own pipeline; the framework gates the image before it leaves CI.'
        : 'This repository ships no container; image, registry and deploy controls are N/A with a reason.'
  ]);
  lines.push('name: Security checks', '', 'on:', '  pull_request:', '    branches:', `      - ${q(config.repository.defaultBranch)}`, '  schedule:', `    - cron: ${q(config.rollout.schedule)}`);
  if (bootstrapAvailable(config)) {
    block(
      lines,
      2,
      [
        'workflow_dispatch:',
        '  inputs:',
        '    bootstrap_baseline:',
        '      description: ONE-TIME onboarding - full Semgrep scan against an empty accepted set, uploading a candidate baseline.',
        '      type: boolean',
        '      default: false'
      ].join('\n')
    );
  }
  lines.push('', 'permissions:', '  contents: read', '', 'jobs:');
  lines.push(...sourceSecurityJob(config, { phase: 'pr' }), '');
  if (container) {
    lines.push(...containerBuildJob(config, { phase: 'pr' }), '');
    lines.push(...imageSecurityJob(config, { phase: 'pr' }), '');
  }
  lines.push(...securityGateJob(config), '');
  lines.push(...gateModeJob(config), '');
  lines.push(...conformanceJob(config, { phase: 'pr' }));
  return withMarker(`${lines.join('\n')}\n`);
}

export function renderDeliveryWorkflow(config) {
  const d = config.delivery;
  const branch = config.repository.defaultBranch;
  const lines = [];
  header(config, lines, [
    `DELIVERY phase for ${config.repository.slug}. Each stage holds the least it can:`,
    '  source-security  no cloud credentials at all: it calls the OIDC-free _source-scan.yml and break-glass is disabled',
    '  container-build  no cloud credentials, no build arguments',
    '  image-security   no cloud credentials; records the image config digest Trivy scanned',
    '  ecr-collect      the push+scan role ONLY; asserts loaded image == scanned image, pushes',
    '  artifact-gate    no cloud credentials; judges the registry scan of the pushed digest',
    '  deploy           the SSM deploy role ONLY; deploys repo@sha256:... , never a tag',
    'Generated only while the repository enforces (ssd-onboard promote --enforce).'
  ]);
  lines.push('name: Deploy', '', 'on:', '  push:', '    branches:', `      - ${q(branch)}`, '  workflow_dispatch:', '', 'permissions:', '  contents: read', '', 'jobs:');
  lines.push(...sourceSecurityJob(config, { phase: 'delivery' }), '');
  lines.push(...containerBuildJob(config, { phase: 'delivery' }), '');
  lines.push(...imageSecurityJob(config, { phase: 'delivery' }), '');
  const ecr = ['  ecr-collect:'];
  block(
    ecr,
    4,
    [
      '# THE FIRST job to hold a registry credential, and the only one that does.',
      'needs:',
      '  - source-security',
      '  - container-build',
      '  - image-security',
      'if: >-',
      `  github.ref == 'refs/heads/${branch}' &&`,
      "  needs.source-security.result == 'success' &&",
      "  needs.image-security.result == 'success'",
      `uses: ${reusable(config, '_ecr-collect.yml')}`,
      'permissions:',
      '  contents: read',
      '  id-token: write',
      'with:',
      ...toolkitInputs(config).map((line) => `  ${line}`),
      `  image_artifact: ${imageArtifact()}`,
      `  local_image_ref: ${config.container.imageName}:\${{ github.sha }}`,
      '  # Digest chain: the image config digest Trivy actually scanned.',
      '  expected_image_id: ${{ needs.image-security.outputs.image_id }}',
      `  role_arn: ${q(d.roles.pushScanRoleArn)}`,
      `  aws_region: ${q(d.aws.region)}`,
      `  ecr_repository: ${q(d.ecr.repository)}`,
      '  immutable_tag: ${{ github.sha }}'
    ].join('\n')
  );
  lines.push(...ecr, '');
  const gate = ['  artifact-gate:'];
  block(
    gate,
    4,
    [
      '# NO cloud credentials, names no registry. A failure here skips `deploy` entirely.',
      'needs: ecr-collect',
      `uses: ${reusable(config, '_artifact-gate.yml')}`,
      'permissions:',
      '  contents: read'
    ].join('\n')
  );
  slackSecret(gate, config, 4);
  block(
    gate,
    4,
    [
      'with:',
      ...toolkitInputs(config).map((line) => `  ${line}`),
      '  report_artifact: ${{ needs.ecr-collect.outputs.report_artifact }}',
      '  report_path: ${{ needs.ecr-collect.outputs.report_path }}',
      '  # Re-assert the exact manifest digest that was pushed and scanned.',
      '  expected_digest: ${{ needs.ecr-collect.outputs.image_digest }}',
      '  gate_mode: enforce'
    ].join('\n')
  );
  lines.push(...gate, '');
  const deploy = ['  deploy:'];
  block(
    deploy,
    4,
    [
      'name: Deploy',
      '# The SSM deploy role and nothing else: no ECR access. The instance pulls the',
      '# image with its OWN read-only role, so push credentials never reach the box.',
      'needs:',
      '  - artifact-gate',
      '  - ecr-collect',
      ...(d.environment ? [`environment: ${q(d.environment)}`] : []),
      'runs-on: ubuntu-latest',
      'permissions:',
      '  contents: read',
      '  id-token: write',
      'steps:',
      '  - name: Check out the framework toolkit for the deploy script',
      `    uses: ${ACTIONS.checkout}`,
      '    with:',
      `      repository: ${config.framework.repository}`,
      `      ref: ${config.framework.ref}`,
      '      path: .ssd-toolkit',
      '      persist-credentials: false',
      '  - name: Set up Node.js',
      `    uses: ${ACTIONS.setupNode}`,
      '    with:',
      `      node-version: ${q(NODE_VERSION)}`,
      '      package-manager-cache: false',
      '  - name: Assume the SSM deploy role (SSM only)',
      `    uses: ${ACTIONS.configureAwsCredentials}`,
      '    with:',
      `      role-to-assume: ${q(d.roles.deployRoleArn)}`,
      `      aws-region: ${q(d.aws.region)}`,
      '      role-session-name: ssd-deploy',
      '  - name: Deploy the approved digest over SSM',
      '    env:',
      `      AWS_REGION: ${q(d.aws.region)}`,
      '      ECR_REGISTRY: ${{ needs.ecr-collect.outputs.registry }}',
      '      # The last link: the exact manifest that was scanned and gated, by digest.',
      '      IMAGE_DIGEST: ${{ needs.ecr-collect.outputs.image_digest }}',
      '    run: |',
      '      node .ssd-toolkit/security/scripts/ssm-deploy.mjs \\',
      `        --instance-id ${d.ssm.instanceId} \\`,
      '        --region "$AWS_REGION" \\',
      '        --registry "$ECR_REGISTRY" \\',
      `        --repository ${d.ecr.repository} \\`,
      '        --image-digest "$IMAGE_DIGEST" \\',
      `        --container-name ${d.ssm.containerName} \\`,
      `        --app-port ${d.ssm.appPort}`
    ].join('\n')
  );
  lines.push(...deploy, '');
  lines.push(...conformanceJob(config, { phase: 'delivery' }));
  return withMarker(`${lines.join('\n')}\n`);
}

export function renderSemgrepignore(config) {
  const lines = [
    '#',
    '# Semgrep ignore list for SAST, read from the repository root.',
    '#',
    "# This file REPLACES Semgrep's built-in default ignore list. Without it, Semgrep",
    '# silently skips tests/, test/, build/, dist/, vendor/, node_modules/, *.min.js',
    '# and more. Only the patterns below are excluded; with none, every tracked',
    `# file under the configured roots (${config.semgrep.roots.join(' ')}) is scanned.`,
    '#',
    '# Patterns come from semgrep.ignore.patterns in .ssd/onboarding.yml.'
  ];
  if (config.semgrep.ignore.patterns.length === 0) {
    lines.push('# (no exclusions)');
  } else {
    lines.push(...config.semgrep.ignore.patterns);
  }
  return withMarker(`${lines.join('\n')}\n`);
}

const tomlBasic = (value) => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
const tomlLiteral = (value) => `'''${value}'''`;

export function renderGitleaksToml(config) {
  const g = config.gitleaks;
  const lines = [
    '#',
    `# Gitleaks configuration for ${config.repository.slug}.`,
    '#',
    `title = ${tomlBasic(`${config.repository.slug} (generated by ssd-onboard)`)}`,
    '',
    '[extend]',
    '# KEEP the built-in ruleset. A config with rules but without this line REPLACES',
    '# every default rule (verified against the framework\'s pinned Gitleaks).',
    'useDefault = true'
  ];
  for (const rule of g.customRules) {
    lines.push('', '[[rules]]', `id = ${tomlBasic(rule.id)}`, `description = ${tomlBasic(rule.description)}`, `regex = ${tomlLiteral(rule.regex)}`);
    if (rule.keywords.length > 0) {
      lines.push(`keywords = [${rule.keywords.map(tomlBasic).join(', ')}]`);
    }
  }
  for (const allowlist of g.allowlists) {
    lines.push('', '# A reviewed, owner-authored allowlist. ssd-onboard never proposes one.', '[[allowlists]]', `description = ${tomlBasic(allowlist.description)}`);
    if (allowlist.paths.length > 0) {
      lines.push(`paths = [${allowlist.paths.map(tomlLiteral).join(', ')}]`);
    }
    if (allowlist.regexes.length > 0) {
      lines.push(`regexes = [${allowlist.regexes.map(tomlLiteral).join(', ')}]`);
    }
  }
  return withMarker(`${lines.join('\n')}\n`);
}

// The complete set of files this config produces, in a stable order.
export function renderAll(config) {
  const files = [{ path: config.workflows.security, kind: 'workflow', content: renderSecurityWorkflow(config) }];
  if (isEcrProfile(config.profile) && config.rollout.gateMode === 'enforce') {
    files.push({ path: config.workflows.delivery, kind: 'workflow', content: renderDeliveryWorkflow(config) });
  }
  if (config.semgrep.ignore.managed) {
    files.push({ path: '.semgrepignore', kind: 'scanner-config', content: renderSemgrepignore(config) });
  }
  if (config.gitleaks.mode === 'managed') {
    files.push({ path: config.gitleaks.path, kind: 'scanner-config', content: renderGitleaksToml(config) });
  }
  return files;
}
