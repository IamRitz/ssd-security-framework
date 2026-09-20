// Developer-readable notifier: reads a gate JSON result, builds the shared
// report, and delivers it to the surfaces the routing rules select.
//
//   BLOCK / BLOCK_DEPLOY / integrity -> Slack + PR comment + job summary
//   EXCEPTION-only                   -> PR comment + job summary (no ping)
//   clean PASS / DEPLOY              -> PR comment + job summary (no ping)
//   gate_mode: log-only              -> never Slack
//   break-glass request DELIVERED    -> no plain ping (the interactive request
//                                       already reached approvers)
//
// Break-glass ELIGIBILITY never suppresses Slack on its own. Whether a request
// was actually made and delivered is observed state, passed in explicitly by
// the workflow (BREAK_GLASS_* below) — never inferred from the gate's policy
// eligibility. See deriveBreakGlassState in format-findings.mjs.
//
// The interactive break-glass flow itself (break-glass-notify.mjs + the broker)
// is untouched; this module only adds the read-only developer feedback surfaces
// around it.

import { appendFile, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildReport,
  deriveBreakGlassState,
  renderEvidenceMarkdown,
  renderBreakGlassFindingsPointer,
  renderMarkdown,
  renderSlack,
  resolveReproduceCommands,
  PR_COMMENT_MARKER
} from './format-findings.mjs';

// --- surface implementations (injectable for tests) --------------------------

export async function writeStepSummary(markdown, { summaryPath, appendImpl = appendFile } = {}) {
  if (!summaryPath) {
    return false;
  }
  await appendImpl(summaryPath, markdown);
  return true;
}

// A GitHub API response the notifier could not act on, with its status kept so
// the caller can tell "not permitted" from "broken".
export class GitHubApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'GitHubApiError';
    this.status = status;
  }
}

// Find-by-marker then update, so repeated pushes update one comment instead of
// stacking walls of findings on the PR.
//
// `updateOnly` (used for a clean run): update an existing findings comment —
// e.g. flip an earlier ⛔ BLOCK to ✅ once fixed — but do NOT create a new one.
// A PR that was always clean then gets no status comment at all, rather than a
// "No findings" comment nobody needed.
//
// A skip carries a `category`:
//   not-applicable  no pull request is associated with this run (push, schedule,
//                   workflow_dispatch without pr_number, a post-push gate). The
//                   expected state — never an error.
//   permission      no token was provided at all.
//   clean-no-comment clean run with nothing to update.
export async function upsertPrComment({
  repository,
  prNumber,
  token,
  body,
  updateOnly = false,
  eventName = null,
  fetchImpl = globalThis.fetch
}) {
  if (!prNumber) {
    return {
      skipped: true,
      category: 'not-applicable',
      reason: `no pull request is associated with this run (event: ${eventName || 'unknown'})`
    };
  }
  if (!repository) {
    return { skipped: true, category: 'not-applicable', reason: 'no repository context for this run' };
  }
  if (!token) {
    return { skipped: true, category: 'permission', reason: 'no GitHub token was provided to the notifier' };
  }
  const api = `https://api.github.com/repos/${repository}/issues/${prNumber}/comments`;
  const headers = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'content-type': 'application/json'
  };

  const timeout = () => globalThis.AbortSignal.timeout(15_000);
  const listResponse = await fetchImpl(`${api}?per_page=100`, { headers, signal: timeout() });
  if (!listResponse.ok) {
    throw new GitHubApiError(`listing PR comments failed: HTTP ${listResponse.status}`, listResponse.status);
  }
  const existing = (await listResponse.json()).find(
    (comment) => typeof comment.body === 'string' && comment.body.includes(PR_COMMENT_MARKER)
  );

  if (existing) {
    const patch = await fetchImpl(
      `https://api.github.com/repos/${repository}/issues/comments/${existing.id}`,
      { method: 'PATCH', headers, body: JSON.stringify({ body }), signal: timeout() }
    );
    if (!patch.ok) {
      throw new GitHubApiError(`updating PR comment failed: HTTP ${patch.status}`, patch.status);
    }
    return { updated: true, id: existing.id };
  }

  if (updateOnly) {
    // Clean run and no prior findings comment to resolve — post nothing.
    return {
      skipped: true,
      category: 'clean-no-comment',
      reason: 'clean run with no existing comment to update'
    };
  }

  const create = await fetchImpl(api, {
    method: 'POST',
    headers,
    body: JSON.stringify({ body }),
    signal: timeout()
  });
  if (!create.ok) {
    throw new GitHubApiError(`creating PR comment failed: HTTP ${create.status}`, create.status);
  }
  return { created: true };
}

// Classify a thrown PR-comment error. A 403 on a FORK pull request is the
// expected, safe outcome: the `pull_request` event (never `pull_request_target`)
// gives fork code a read-only token, so no comment can be written. Anywhere else
// a 403 means the calling workflow did not grant `pull-requests: write`, which is
// a configuration problem worth failing loudly on. Anything else is an API failure.
export function classifyPrCommentError(error, { isForkPullRequest = false } = {}) {
  const status = error?.status;
  if ((status === 403 || status === 401) && isForkPullRequest) {
    return {
      category: 'fork-read-only',
      expected: true,
      reason:
        `GitHub denied the comment (HTTP ${status}) on a fork pull request. Fork PRs get a read-only token by ` +
        'design, so the findings are in this job summary instead.'
    };
  }
  if (status === 403 || status === 401) {
    return {
      category: 'permission',
      expected: false,
      reason:
        `GitHub denied the comment (HTTP ${status}). The calling workflow must grant \`pull-requests: write\` ` +
        'to the security job.'
    };
  }
  return { category: 'api-failure', expected: false, reason: error?.message || String(error) };
}

export async function postSlack({ url, message, fetchImpl = globalThis.fetch }) {
  if (!url) {
    return { skipped: true, reason: 'no Slack notify URL configured' };
  }
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(message),
    signal: globalThis.AbortSignal.timeout(15_000)
  });
  if (!response.ok) {
    throw new Error(`Slack notification failed: HTTP ${response.status}`);
  }
  return { posted: true };
}

const SLACK_SUPPRESSED = {
  'log-only': 'NOTIFY: Slack suppressed — gate_mode is log-only',
  'break-glass-request-delivered':
    'NOTIFY: Slack suppressed — an interactive break-glass request was delivered for this BLOCK',
  'non-blocking-verdict': 'NOTIFY: Slack not routed — verdict is not blocking'
};

// --- orchestration -----------------------------------------------------------

export async function dispatch({
  gate,
  context = {},
  mode = 'enforce',
  breakGlass,
  slackUrl,
  token,
  summaryPath,
  evidencePath,
  fetchImpl,
  appendImpl,
  writeImpl = writeFile,
  logger = console
}) {
  const report = buildReport({ gate, context, mode, breakGlass });
  const { routing } = report;
  const performed = {
    verdict: report.verdict,
    slack: false,
    prComment: false,
    summary: false,
    breakGlass: report.breakGlass
  };
  const failures = [];
  const notes = [];

  // 1. Job summary FIRST and unconditionally — it is a local file write with no
  //    network, so the full, plain-language explanation lands even if every
  //    remote surface below fails. This is the guarantee against the worst case:
  //    a red pipeline (from the gate's own failing step) with no reason shown.
  //    In the break-glass job (context.summaryRole) the findings already live in
  //    the source-gate summary, so only a pointer is written; the surfaces below
  //    are unaffected by the role.
  if (routing.summary) {
    const summary =
      context.summaryRole === 'break-glass'
        ? renderBreakGlassFindingsPointer(report)
        : renderMarkdown(report, { includeMarker: false });
    try {
      performed.summary = await writeStepSummary(summary, {
        summaryPath,
        appendImpl
      });
    } catch (error) {
      failures.push(`job summary (${error.message})`);
      logger.error?.(`NOTIFY: job summary write failed: ${error.message}`);
    }
  }

  // 1b. The full evidence document: every issue's complete explanation, which
  //     the bounded summary and comment do not repeat. Local, best effort.
  if (evidencePath) {
    try {
      await writeImpl(evidencePath, renderEvidenceMarkdown(report));
    } catch (error) {
      logger.error?.(`NOTIFY: evidence document write failed: ${error.message}`);
    }
  }

  // 2. PR comment and 3. Slack are independent: a failure in one never suppresses
  //    the other, and neither can suppress the summary already written above.
  // A clean run has nothing actionable to report (no blocking, exception, or
  // integrity findings). We still update an existing comment — to flip a prior
  // red one to green — but we do not create a new comment just to say "clean".
  const clean =
    report.counts.block === 0 && report.counts.exception === 0 && report.counts.integrity === 0;

  if (routing.prComment) {
    try {
      const result = await upsertPrComment({
        repository: context.repository,
        prNumber: context.prNumber,
        token,
        body: renderMarkdown(report, { includeMarker: true }),
        updateOnly: clean,
        eventName: context.eventName,
        fetchImpl
      });
      performed.prComment = !result.skipped;
      if (result.skipped) {
        performed.prCommentSkip = result.category;
        if (result.category === 'permission') {
          failures.push(`PR comment (${result.reason})`);
          logger.error?.(`NOTIFY: PR comment not posted: ${result.reason}`);
        } else {
          const label = result.category === 'not-applicable' ? 'not applicable' : 'skipped';
          logger.log?.(`NOTIFY: PR comment ${label}: ${result.reason}`);
        }
      }
    } catch (error) {
      const classified = classifyPrCommentError(error, { isForkPullRequest: context.isForkPullRequest });
      performed.prCommentSkip = classified.category;
      if (classified.expected) {
        notes.push(`PR comment not posted: ${classified.reason}`);
        logger.log?.(`NOTIFY: PR comment not posted (expected): ${classified.reason}`);
      } else {
        failures.push(`PR comment (${classified.reason})`);
        logger.error?.(`NOTIFY: PR comment failed [${classified.category}]: ${classified.reason}`);
      }
    }
  }

  if (routing.slack) {
    try {
      const result = await postSlack({ url: slackUrl, message: renderSlack(report), fetchImpl });
      performed.slack = !result.skipped;
      if (result.skipped) {
        logger.log?.(`NOTIFY: Slack notification skipped: ${result.reason}`);
      }
    } catch (error) {
      failures.push(`Slack (${error.message})`);
      logger.error?.(`NOTIFY: Slack notification failed: ${error.message}`);
    }
  } else {
    logger.log?.(SLACK_SUPPRESSED[routing.slackReason] || `NOTIFY: Slack not routed (${routing.slackReason})`);
  }

  // Record remote-surface outcomes in the local summary too, so a failure is
  // visible as "notification failed" rather than a silently missing channel, and
  // an expected non-delivery is explained rather than looking like a failure.
  // Best effort — never throws.
  if (routing.summary && performed.summary && (failures.length > 0 || notes.length > 0)) {
    const lines = [];
    if (failures.length > 0) {
      lines.push(
        `\n> ⚠️ **Notification delivery incomplete:** ${failures.join('; ')}. ` +
          'The findings above are complete; only remote delivery failed.\n'
      );
    }
    for (const note of notes) {
      lines.push(`\n> ℹ️ ${note}\n`);
    }
    try {
      await writeStepSummary(lines.join(''), { summaryPath, appendImpl });
    } catch {
      // The primary summary already landed; a footer failure is not worth crashing.
    }
  }

  return { ...performed, failures, notes };
}

// --- CLI ---------------------------------------------------------------------

function parseArguments(argv) {
  const options = { gate: 'reports/security-gate.json', mode: 'enforce' };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (key === '--gate') options.gate = value;
    else if (key === '--mode') options.mode = value;
    else throw new Error(`unknown or incomplete argument ${key}`);
  }
  return options;
}

// Optional JSON artifact: absent or unreadable is "no evidence", never an error.
async function readOptionalJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

async function fileExists(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

const words = (value) =>
  typeof value === 'string' ? value.split(/\s+/).filter((word) => word !== '') : [];

// The break-glass state channel. Unset BREAK_GLASS_ENABLED means the caller did
// not pass the state at all (a gate with no break-glass concept, or an older
// workflow): `enabled` is then unknown and nothing is claimed.
export async function breakGlassStateFromEnv(env, { gate, mode }) {
  const rawEnabled = env.BREAK_GLASS_ENABLED;
  const enabled = rawEnabled === 'true' ? true : rawEnabled === 'false' ? false : null;
  return deriveBreakGlassState({
    verdict: gate?.verdict,
    eligible: gate?.breakGlass?.eligible === true,
    mode,
    enabled,
    checkOutcome: env.BREAK_GLASS_CHECK_OUTCOME || '',
    requestOutcome: env.BREAK_GLASS_REQUEST_OUTCOME || '',
    pollOutcome: env.BREAK_GLASS_POLL_OUTCOME || '',
    request: await readOptionalJson(env.BREAK_GLASS_REQUEST_PATH || 'reports/break-glass-request.json'),
    decision: await readOptionalJson(env.BREAK_GLASS_DECISION_PATH || 'reports/break-glass-decision.json'),
    // Explicit workflow output, never inferred from eligibility or `enabled`.
    delegated: env.BREAK_GLASS_DELEGATED === 'true'
  });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const gate = JSON.parse(await readFile(options.gate, 'utf8'));
  const env = process.env;
  const headRepository = env.PR_HEAD_REPOSITORY || '';
  // Written next to the gate result and uploaded with it.
  const evidencePath = join(dirname(options.gate), `${basename(options.gate, '.json')}-evidence.md`);
  const context = {
    evidenceFile: basename(options.gate),
    evidenceMarkdownFile: basename(evidencePath),
    // `break-glass` only in the Lambda break-glass job: its job summary then
    // carries a pointer to the source findings instead of repeating them.
    summaryRole: env.SECURITY_SUMMARY_ROLE === 'break-glass' ? 'break-glass' : null,
    // The raw scanner report behind this gate result, when the workflow names
    // one (image gates). Only its file name is shown.
    rawReportFile: env.SECURITY_RAW_REPORT ? basename(env.SECURITY_RAW_REPORT) : null,
    // Each scanner job's own result (source workflow only), for scan health.
    jobResults: {
      'secret-scan': env.SECRET_SCAN_JOB_RESULT,
      'dependency-scan': env.DEPENDENCY_SCAN_JOB_RESULT,
      sast: env.SAST_JOB_RESULT
    },
    repository: env.GITHUB_REPOSITORY,
    sha: env.GITHUB_SHA,
    prNumber: env.PR_NUMBER || null,
    eventName: env.GITHUB_EVENT_NAME || null,
    isForkPullRequest: headRepository !== '' && headRepository !== env.GITHUB_REPOSITORY,
    runUrl:
      env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
        ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
        : null,
    // Per-repo "reproduce this locally" commands. Unset falls back to direct
    // scanner invocations that hold in any repo, never to this repo's Makefile.
    reproduceCommands: resolveReproduceCommands(env.SECURITY_REPRODUCE_COMMANDS),
    // What this run actually scanned with, so reproduce commands match it. A
    // config file is named only if it exists — the scan jobs omit absent ones.
    scan: {
      semgrepConfigs: words(env.SEMGREP_CONFIGS),
      semgrepPaths: words(env.SEMGREP_PATHS),
      gitleaksConfig: env.GITLEAKS_CONFIG && (await fileExists(env.GITLEAKS_CONFIG)) ? env.GITLEAKS_CONFIG : null,
      trufflehogExcludePaths:
        env.TRUFFLEHOG_EXCLUDE_PATHS && (await fileExists(env.TRUFFLEHOG_EXCLUDE_PATHS))
          ? env.TRUFFLEHOG_EXCLUDE_PATHS
          : null,
      imageTarball: env.SSD_IMAGE_TARBALL || null
    }
  };
  // gate_mode drives Slack suppression; a repo still in log-only pages no one.
  const mode = (env.GATE_MODE || options.mode || 'enforce').toLowerCase();

  const performed = await dispatch({
    gate,
    context,
    mode,
    breakGlass: await breakGlassStateFromEnv(env, { gate, mode }),
    slackUrl: env.SECURITY_NOTIFY_SLACK_URL,
    token: env.GITHUB_TOKEN,
    summaryPath: env.GITHUB_STEP_SUMMARY,
    evidencePath
  });

  const bg = performed.breakGlass;
  console.log(
    `Notified verdict=${performed.verdict} slack=${performed.slack} pr=${performed.prComment} summary=${performed.summary} ` +
      `break-glass: eligible=${bg.eligible} enabled=${bg.enabled ?? 'unknown'} pathEntered=${bg.requestPathEntered} requested=${bg.requested} ` +
      `delivered=${bg.delivered} decision=${bg.decision}`
  );
  // Mark the step failed in its own log when a remote surface could not be
  // delivered. The gate's verdict is decided by a different step, so this never
  // masks (or manufactures) the pass/fail signal; with continue-on-error on the
  // workflow step it does not fail the job — it just makes the delivery gap
  // legible to anyone reading the run. Expected non-delivery (no PR, fork PR) is
  // not a failure.
  if (performed.failures.length > 0) {
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
