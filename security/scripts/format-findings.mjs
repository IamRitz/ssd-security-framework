// Shared developer-readable formatter for every pipeline failure point.
//
// One structured finding shape, three thin renderers (Slack Block Kit, PR
// comment markdown, and $GITHUB_STEP_SUMMARY markdown). Consistency is by
// construction: a change to the finding shape or the plain-language derivation
// updates every surface at once, because every surface reads the same
// normalized objects produced by `buildReport`.
//
// Input is the JSON a gate already wrote (reports/security-gate.json or
// reports/image-gate*.json) — the reviewed verdict is the source of truth. The
// formatter only makes that verdict legible to a developer who is not a
// security specialist; it never re-decides policy. Human context fields
// (Semgrep `message`, advisory summary, CVE description, fixed version) are
// surfaced when the gate captured them and degrade gracefully when it did not,
// so a minimal finding still renders a useful, plain-language card.

export const PR_COMMENT_MARKER = '<!-- security-gate-findings -->';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };

// Verdict -> how the header reads on every surface. Each verdict is visibly
// distinct (label + emoji + one-line meaning) so BLOCK, EXCEPTION and a clean
// pass are never confused with one another.
const VERDICTS = {
  PASS: { emoji: '✅', label: 'PASS', blurb: 'No blocking security findings.' },
  'PASS-WITH-EXCEPTIONS': {
    emoji: '⚠️',
    label: 'EXCEPTION',
    blurb: 'Passed with tracked exceptions — Critical/High findings with no upstream fix.'
  },
  BLOCK: { emoji: '⛔', label: 'BLOCK', blurb: 'Blocking security findings must be resolved before merge.' },
  DEPLOY: { emoji: '✅', label: 'DEPLOY', blurb: 'Image cleared for deploy.' },
  'DEPLOY-WITH-EXCEPTIONS': {
    emoji: '⚠️',
    label: 'DEPLOY-WITH-EXCEPTIONS',
    blurb: 'Deploying with tracked image exceptions — Critical/High with no upstream fix.'
  },
  BLOCK_DEPLOY: { emoji: '⛔', label: 'BLOCK_DEPLOY', blurb: 'Blocking image findings must be resolved before deploy.' }
};

// How a developer reproduces a finding locally. Telling someone in another repo
// to run `make sast` when they have no Makefile is worse than telling them
// nothing, so the defaults are direct scanner invocations that hold anywhere. A
// repo with its own wrapper (this one has a Makefile) overrides them through the
// `reproduce_commands` workflow input -> SECURITY_REPRODUCE_COMMANDS.
export const DEFAULT_REPRODUCE_COMMANDS = {
  gitleaks: 'gitleaks git . --redact=100',
  trufflehog: 'trufflehog git file://. --results=verified,unverified,unknown',
  'npm-audit': 'npm audit --package-lock-only',
  'pip-audit': 'pip-audit --requirement requirements.txt --no-deps',
  'osv-scanner': 'osv-scanner scan source --recursive .',
  semgrep: 'semgrep scan --config p/owasp-top-ten .',
  trivy: 'trivy image --scanners vuln,secret <image>',
  'ecr-image-scan': 'trivy image --scanners vuln,secret <image>',
  'ecr-enhanced-scan': 'trivy image --scanners vuln,secret <image>'
};

// Parses the SECURITY_REPRODUCE_COMMANDS override. Malformed JSON falls back to
// the portable defaults rather than crashing the notifier — this is developer
// guidance, never a gate input, so it must never be able to fail a run.
export function resolveReproduceCommands(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return DEFAULT_REPRODUCE_COMMANDS;
  }

  const overrides = Object.fromEntries(
    Object.entries(parsed).filter(([, value]) => typeof value === 'string' && value !== '')
  );
  return { ...DEFAULT_REPRODUCE_COMMANDS, ...overrides };
}

function titleCase(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function locationParts(location) {
  if (typeof location !== 'string' || location === '') {
    return null;
  }
  // Findings encode location as "path:line"; the line may be "?" when unknown.
  const lastColon = location.lastIndexOf(':');
  if (lastColon === -1) {
    return { path: location, line: null };
  }
  const path = location.slice(0, lastColon);
  const rawLine = location.slice(lastColon + 1);
  const line = /^\d+$/.test(rawLine) ? Number(rawLine) : null;
  return { path, line };
}

function deepLink(context, place) {
  if (!place || !context?.repository || !context?.sha) {
    return null;
  }
  const anchor = place.line ? `#L${place.line}` : '';
  return `https://github.com/${context.repository}/blob/${context.sha}/${place.path}${anchor}`;
}

// Prefer whatever human text the gate captured from the scanner (Semgrep
// message, advisory summary/title, CVE description). Fall back to the gate's
// own machine reason so the card is never empty.
function meaningText(finding, fallback) {
  return (
    finding.message ||
    finding.summary ||
    finding.title ||
    finding.description ||
    fallback ||
    finding.reason ||
    ''
  );
}

function semgrepRuleUrl(checkId) {
  // Registry rules (dotted ids like "javascript.express.security...") resolve at
  // semgrep.dev/r/<id>. Local rule ids (our security/semgrep-rules.yml) do not,
  // so only link ones that look like registry rules.
  if (typeof checkId !== 'string' || !checkId.includes('.') || checkId.startsWith('rules.')) {
    return null;
  }
  return `https://semgrep.dev/r/${checkId}`;
}

const EXCEPTION_FIX =
  'No upstream fix is available yet, so this passed as a tracked EXCEPTION rather than a block. ' +
  "It is not something your change introduced and there is nothing to fix right now — it stays visible and tracked until a fix ships upstream.";

function upgradeHint(finding) {
  const pkg = finding.package || finding.id;
  const version = finding.fixedVersion ? `@${finding.fixedVersion}` : '';
  if (finding.source === 'pip-audit') {
    return `Upgrade \`${pkg}\` to ${finding.fixedVersion || 'a fixed version'} — e.g. \`pip install --upgrade ${pkg}${finding.fixedVersion ? `==${finding.fixedVersion}` : ''}\`.`;
  }
  return `Upgrade \`${pkg}\` to ${finding.fixedVersion || 'a fixed version'} — e.g. \`npm install ${pkg}${version}\` (then commit the lockfile).`;
}

// Turn one decided gate finding into a surface-agnostic, plain-language card.
function classify(finding, context) {
  const severity = (finding.severity || 'none').toLowerCase();
  const place = locationParts(finding.location);
  const isException = finding.action === 'EXCEPTION';
  const reproduce = (context?.reproduceCommands || DEFAULT_REPRODUCE_COMMANDS)[finding.source] || null;
  const link = deepLink(context, place);

  const base = {
    id: finding.id,
    source: finding.source,
    severity,
    action: finding.action,
    policyRule: finding.policyRule,
    package: finding.package || null,
    isException,
    isIntegrity: false,
    location: place,
    deepLink: link,
    reproduce,
    fixAvailable: finding.fixAvailable,
    fixedVersion: finding.fixedVersion || null,
    referenceUrl: finding.url || null
  };

  // Report-integrity: a fail-closed BLOCK that is NOT a vulnerability. Say so
  // plainly so a developer does not hunt for code they never wrote.
  if (finding.policyRule?.endsWith('report_integrity') || finding.id === 'report-integrity') {
    return {
      ...base,
      kind: 'integrity',
      isIntegrity: true,
      title: 'Scan integrity failure — result cannot be trusted',
      whatItMeans:
        `${finding.reason} This is blocked deliberately rather than passed: a scan that could not ` +
        'understand its input cannot prove the artifact is clean.',
      howToFix:
        'This is an integrity failure, not a vulnerability you introduced. Re-run the pipeline; if it ' +
        'persists, check that the scanner produced a complete, well-formed report (a detected base-image ' +
        'OS, a non-empty report file, valid JSON). It is not something to fix in application code.'
    };
  }

  switch (finding.source) {
    case 'gitleaks':
    case 'trufflehog': {
      const verified = finding.policyRule === 'secrets.verified';
      return {
        ...base,
        kind: 'secret',
        title: verified
          ? `Verified leaked credential (\`${finding.id}\`)`
          : `Potential secret detected (\`${finding.id}\`)`,
        whatItMeans: meaningText(
          finding,
          verified
            ? 'A scanner confirmed this credential is live with its provider. Treat it as compromised.'
            : 'A pattern matching a secret was found. Confirm whether it is a real credential.'
        ),
        howToFix: verified
          ? 'Rotate/revoke the credential now, then remove it from history. Verified secrets are never break-glass eligible.'
          : 'Confirm whether this is a real secret. If so, rotate it and remove it from the repository; if not, add it to the ignore configuration.'
      };
    }
    case 'npm-audit':
    case 'pip-audit':
    case 'osv-scanner': {
      const pkg = finding.package || finding.id;
      return {
        ...base,
        kind: 'dependency',
        title: `${titleCase(severity)}-severity vulnerability in dependency \`${pkg}\` (${finding.id})`,
        whatItMeans: meaningText(
          finding,
          `${titleCase(severity)} advisory ${finding.id} affects \`${pkg}\`.`
        ),
        howToFix: isException ? EXCEPTION_FIX : upgradeHint(finding)
      };
    }
    case 'semgrep': {
      const path = place?.path || 'the changed code';
      const state = finding.baselineState === 'existing' ? 'Pre-existing' : 'New';
      const ruleUrl = semgrepRuleUrl(finding.id);
      return {
        ...base,
        kind: 'sast',
        referenceUrl: base.referenceUrl || ruleUrl,
        title: `${state} ${severity}-severity code security issue in \`${path}\``,
        whatItMeans: meaningText(
          finding,
          `Semgrep rule \`${finding.id}\` flagged this line as a likely security issue.`
        ),
        howToFix: isException
          ? EXCEPTION_FIX
          : `Review the flagged line and remediate the pattern.${
              ruleUrl ? ` Rule reference: ${ruleUrl}` : ` Rule: \`${finding.id}\`.`
            }`
      };
    }
    case 'trivy': {
      if (finding.policyRule === 'image.secret') {
        return {
          ...base,
          kind: 'image-trivy',
          severity: 'critical',
          title: `Secret baked into an image layer (\`${finding.id}\`)`,
          whatItMeans:
            meaningText(finding, `A secret was detected inside a built image layer (${finding.id}).`),
          howToFix:
            'Remove the secret from the build (do not COPY credentials into layers; use build secrets or runtime injection), ' +
            'rotate the exposed credential, and rebuild. A layer secret is a hard block and is never break-glass eligible.'
        };
      }
      const pkg = finding.package || finding.id;
      return {
        ...base,
        kind: 'image-trivy',
        title: `${titleCase(severity)}-severity vulnerability in image package \`${pkg}\` (${finding.id})`,
        whatItMeans: meaningText(
          finding,
          `${titleCase(severity)} vulnerability ${finding.id} in image package \`${pkg}\`.`
        ),
        howToFix: isException
          ? EXCEPTION_FIX
          : finding.fixedVersion
            ? `Upgrade image package \`${pkg}\` to ${finding.fixedVersion}, or bump the base image to a build that ships the fixed package.`
            : `Upgrade image package \`${pkg}\` to a fixed version, or bump the base image to a build that ships the fix.`
      };
    }
    case 'ecr-enhanced-scan': {
      // Amazon Inspector (ECR enhanced scanning) reports fix availability, so a
      // registry finding can be an EXCEPTION exactly like a Trivy one.
      const pkg = finding.package || 'the affected package';
      return {
        ...base,
        kind: 'image-ecr-enhanced',
        title: `${titleCase(severity)}-severity vulnerability in image (${finding.id})`,
        whatItMeans: meaningText(
          finding,
          `Amazon Inspector reported ${finding.id} at ${severity} severity in the pushed image.`
        ),
        howToFix: isException
          ? EXCEPTION_FIX
          : finding.fixedVersion
            ? `Upgrade image package \`${pkg}\` to ${finding.fixedVersion}, or bump the base image to a build that ships the fixed package.`
            : `Upgrade image package \`${pkg}\` to a fixed version, or bump the base image to a build that ships the fix.`
      };
    }
    case 'ecr-image-scan': {
      // ECR basic scanning reports no fix data — severity only.
      return {
        ...base,
        kind: 'image-ecr',
        title: `${titleCase(severity)}-severity vulnerability in image (${finding.id})`,
        whatItMeans: meaningText(
          finding,
          `ECR basic scanning reported ${finding.id} at ${severity} severity. ECR does not report fix availability.`
        ),
        howToFix:
          'ECR basic scanning does not report a fixed version. Identify the affected OS/library package (a Trivy ' +
          'scan of the same image lists package and fixed version), then upgrade that package or the base image.'
      };
    }
    default:
      return {
        ...base,
        kind: 'other',
        title: `${titleCase(severity)} finding ${finding.id}`,
        whatItMeans: meaningText(finding, finding.reason || ''),
        howToFix: isException ? EXCEPTION_FIX : finding.reason || ''
      };
  }
}

// Notification routing. Returns which surfaces receive this report.
//   BLOCK / BLOCK_DEPLOY / integrity  -> Slack + PR comment + summary
//   EXCEPTION-only verdict            -> PR comment + summary (visible, no ping)
//   clean PASS / DEPLOY               -> PR comment + summary (keeps a stale red
//                                        comment honest), no ping
//   gate_mode: log-only               -> never Slack (a LOG repo pages no one)
//   break-glass eligible BLOCK        -> no plain Slack ping here; the existing
//                                        interactive break-glass message owns Slack
export function route({ verdict, isBreakGlassEligible = false, mode = 'enforce' }) {
  const blocking = verdict === 'BLOCK' || verdict === 'BLOCK_DEPLOY';
  const prComment = true;
  const summary = true;
  let slack = blocking;
  if (mode === 'log-only') {
    slack = false;
  }
  if (isBreakGlassEligible) {
    slack = false;
  }
  return { slack, prComment, summary };
}

// Normalize a gate JSON result into the report every renderer consumes.
export function buildReport({ gate, context = {}, mode = 'enforce' }) {
  const verdict = gate?.verdict || 'BLOCK';
  const meta = VERDICTS[verdict] || VERDICTS.BLOCK;
  const findings = Array.isArray(gate?.findings) ? gate.findings : [];
  const cards = findings.map((finding) => classify(finding, context));
  const isBreakGlassEligible = gate?.breakGlass?.eligible === true;

  const counts = {
    block: cards.filter((c) => c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY').length,
    exception: cards.filter((c) => c.action === 'EXCEPTION').length,
    log: cards.filter((c) => c.action === 'LOG').length,
    integrity: cards.filter((c) => c.isIntegrity).length
  };

  return {
    verdict,
    verdictLabel: meta.label,
    emoji: meta.emoji,
    blurb: meta.blurb,
    context,
    mode,
    cards,
    counts,
    isBreakGlassEligible,
    routing: route({ verdict, isBreakGlassEligible, mode })
  };
}

function sortCards(cards) {
  return [...cards].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
}

function contextLine(context) {
  const bits = [];
  if (context.repository) {
    bits.push(`repo [\`${context.repository}\`](https://github.com/${context.repository})`);
  }
  if (context.prNumber) {
    bits.push(`PR [#${context.prNumber}](https://github.com/${context.repository}/pull/${context.prNumber})`);
  }
  if (context.sha) {
    const short = String(context.sha).slice(0, 12);
    bits.push(`commit [\`${short}\`](https://github.com/${context.repository}/commit/${context.sha})`);
  }
  if (context.runUrl) {
    bits.push(`[run log](${context.runUrl})`);
  }
  return bits.join(' · ');
}

// ---- Markdown renderer (PR comment AND $GITHUB_STEP_SUMMARY share it) --------

function renderCardMarkdown(card) {
  const lines = [`**${card.title}**`];
  if (card.whatItMeans) {
    lines.push('', card.whatItMeans);
  }
  const facts = [];
  if (card.deepLink) {
    facts.push(`📍 [\`${card.location.path}${card.location.line ? `:${card.location.line}` : ''}\`](${card.deepLink})`);
  } else if (card.location?.path) {
    facts.push(`📍 \`${card.location.path}\``);
  }
  if (card.reproduce) {
    facts.push(`🔁 Reproduce locally: \`${card.reproduce}\``);
  }
  if (card.howToFix) {
    facts.push(`🔧 ${card.howToFix}`);
  }
  if (card.referenceUrl) {
    facts.push(`🔗 ${card.referenceUrl}`);
  }
  for (const fact of facts) {
    lines.push(`- ${fact}`);
  }
  return lines.join('\n');
}

function renderGroupMarkdown(heading, cards, { collapseOver = 10 } = {}) {
  if (cards.length === 0) {
    return '';
  }
  const sorted = sortCards(cards);
  const body = sorted.map(renderCardMarkdown).join('\n\n');
  const title = `### ${heading} (${cards.length})`;
  if (cards.length > collapseOver) {
    return `${title}\n\n<details><summary>Show ${cards.length} findings</summary>\n\n${body}\n\n</details>`;
  }
  return `${title}\n\n${body}`;
}

export function renderMarkdown(report, { includeMarker = false } = {}) {
  const { counts } = report;
  const blocks = [];
  if (includeMarker) {
    blocks.push(PR_COMMENT_MARKER);
  }
  blocks.push(`## ${report.emoji} Security gate: ${report.verdictLabel}`);
  blocks.push(`_${report.blurb}_`);

  const ctx = contextLine(report.context);
  if (ctx) {
    blocks.push(ctx);
  }

  const summaryBits = [`**${counts.block}** blocking`, `**${counts.exception}** exception`, `**${counts.log}** logged`];
  if (counts.integrity > 0) {
    summaryBits.push(`**${counts.integrity}** integrity`);
  }
  blocks.push(summaryBits.join(' · '));

  if (report.mode === 'log-only') {
    blocks.push('> ℹ️ This repository runs in **log-only** mode: findings are reported but do not block, and no Slack alert is sent.');
  }
  if (report.isBreakGlassEligible) {
    blocks.push('> 🔑 This BLOCK is **break-glass eligible**. An interactive approval request has been sent to Slack — approve or deny it there.');
  }

  const blocking = report.cards.filter((c) => (c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY') && !c.isIntegrity);
  const integrity = report.cards.filter((c) => c.isIntegrity);
  const exceptions = report.cards.filter((c) => c.action === 'EXCEPTION');
  const logged = report.cards.filter((c) => c.action === 'LOG');

  // Actionable groups (integrity, blocking, exceptions) stay visible even at
  // repo scale; only very large lists collapse. LOG noise collapses early.
  const integritySection = renderGroupMarkdown(
    '🚨 Scan integrity failures — fail-closed, not a code defect',
    integrity,
    { collapseOver: 25 }
  );
  if (integritySection) blocks.push(integritySection);
  const blockingSection = renderGroupMarkdown('⛔ Blocking findings', blocking, { collapseOver: 25 });
  if (blockingSection) blocks.push(blockingSection);
  const exceptionSection = renderGroupMarkdown(
    '⚠️ Tracked exceptions (no upstream fix — passed deliberately)',
    exceptions,
    { collapseOver: 25 }
  );
  if (exceptionSection) blocks.push(exceptionSection);
  const loggedSection = renderGroupMarkdown('📝 Logged (non-blocking)', logged, { collapseOver: 5 });
  if (loggedSection) blocks.push(loggedSection);

  if (report.cards.length === 0) {
    blocks.push('No findings. 🎉');
  }

  return blocks.filter(Boolean).join('\n\n') + '\n';
}

// ---- Slack Block Kit renderer (concise: what/where/how many + link) ---------

function slackCardLine(card) {
  const loc = card.deepLink ? `<${card.deepLink}|${card.location.path}${card.location.line ? `:${card.location.line}` : ''}>` : '';
  return `• *${card.title}*${loc ? `\n   ${loc}` : ''}`;
}

export function renderSlack(report, { detailUrl } = {}) {
  const { counts } = report;
  const headline = `${report.emoji} Security gate: ${report.verdictLabel}`;
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: headline } },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Blocking*\n${counts.block}` },
        { type: 'mrkdwn', text: `*Exceptions*\n${counts.exception}` },
        { type: 'mrkdwn', text: `*Logged*\n${counts.log}` },
        { type: 'mrkdwn', text: `*Repository*\n${report.context.repository || 'n/a'}` }
      ]
    }
  ];

  // Concise: show the most severe blocking/integrity findings only; full detail
  // lives in the PR comment / job summary, which is linked below.
  const highlights = sortCards(
    report.cards.filter((c) => c.action === 'BLOCK' || c.action === 'BLOCK_DEPLOY' || c.isIntegrity)
  ).slice(0, 5);
  if (highlights.length > 0) {
    const shown = highlights.map(slackCardLine).join('\n');
    const remaining = counts.block - highlights.length;
    const more = remaining > 0 ? `\n_…and ${remaining} more — see full detail._` : '';
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `${shown}${more}` } });
  }

  const links = [];
  if (report.context.prNumber && report.context.repository) {
    links.push(`<https://github.com/${report.context.repository}/pull/${report.context.prNumber}|View PR comment for full detail>`);
  } else if (detailUrl) {
    links.push(`<${detailUrl}|Full detail>`);
  }
  if (report.context.runUrl) {
    links.push(`<${report.context.runUrl}|Run log>`);
  }
  if (links.length > 0) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: links.join('  ·  ') }] });
  }

  return { text: headline, blocks };
}
