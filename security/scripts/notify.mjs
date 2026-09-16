// Developer-readable notifier: reads a gate JSON result, builds the shared
// report, and delivers it to the surfaces the routing rules select.
//
//   BLOCK / BLOCK_DEPLOY / integrity -> Slack + PR comment + job summary
//   EXCEPTION-only                   -> PR comment + job summary (no ping)
//   clean PASS / DEPLOY              -> PR comment + job summary (no ping)
//   gate_mode: log-only              -> never Slack
//   break-glass eligible BLOCK       -> no plain ping (interactive Slack owns it)
//
// The existing interactive break-glass Slack flow (break-glass-notify.mjs +
// n8n) is untouched and remains the primary approval path; this module only
// adds the read-only developer feedback surfaces around it.

import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildReport,
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

// Find-by-marker then update, so repeated pushes update one comment instead of
// stacking walls of findings on the PR.
//
// `updateOnly` (used for a clean run): update an existing findings comment —
// e.g. flip an earlier ⛔ BLOCK to ✅ once fixed — but do NOT create a new one.
// A PR that was always clean then gets no status comment at all, rather than a
// "No findings" comment nobody needed.
export async function upsertPrComment({
  repository,
  prNumber,
  token,
  body,
  updateOnly = false,
  fetchImpl = globalThis.fetch
}) {
  if (!repository || !prNumber || !token) {
    return { skipped: true, reason: 'missing repository, prNumber or token' };
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
    // 403 here is the expected, safe outcome on a fork PR: the pull_request event
    // (not pull_request_target) forces a read-only GITHUB_TOKEN, so no comment is
    // ever written from untrusted fork code. Surfaced as a delivery note, not a
    // silent absence — the full findings still land in the local job summary.
    throw new Error(`listing PR comments failed: HTTP ${listResponse.status}`);
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
      throw new Error(`updating PR comment failed: HTTP ${patch.status}`);
    }
    return { updated: true, id: existing.id };
  }

  if (updateOnly) {
    // Clean run and no prior findings comment to resolve — post nothing.
    return { skipped: true, reason: 'clean run with no existing comment to update' };
  }

  const create = await fetchImpl(api, {
    method: 'POST',
    headers,
    body: JSON.stringify({ body }),
    signal: timeout()
  });
  if (!create.ok) {
    throw new Error(`creating PR comment failed: HTTP ${create.status}`);
  }
  return { created: true };
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

// --- orchestration -----------------------------------------------------------

export async function dispatch({
  gate,
  context = {},
  mode = 'enforce',
  slackUrl,
  token,
  summaryPath,
  fetchImpl,
  appendImpl,
  logger = console
}) {
  const report = buildReport({ gate, context, mode });
  const { routing } = report;
  const performed = { verdict: report.verdict, slack: false, prComment: false, summary: false };
  const failures = [];

  // 1. Job summary FIRST and unconditionally — it is a local file write with no
  //    network, so the full, plain-language explanation lands even if every
  //    remote surface below fails. This is the guarantee against the worst case:
  //    a red pipeline (from the gate's own failing step) with no reason shown.
  if (routing.summary) {
    try {
      performed.summary = await writeStepSummary(renderMarkdown(report, { includeMarker: false }), {
        summaryPath,
        appendImpl
      });
    } catch (error) {
      failures.push(`job summary (${error.message})`);
      logger.error?.(`NOTIFY: job summary write failed: ${error.message}`);
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
        fetchImpl
      });
      performed.prComment = !result.skipped;
      if (result.skipped) {
        logger.log?.(`NOTIFY: PR comment skipped: ${result.reason}`);
      }
    } catch (error) {
      failures.push(`PR comment (${error.message})`);
      logger.error?.(`NOTIFY: PR comment failed: ${error.message}`);
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
    logger.log?.(
      report.mode === 'log-only'
        ? 'NOTIFY: Slack suppressed — gate_mode is log-only'
        : report.isBreakGlassEligible
          ? 'NOTIFY: Slack suppressed — interactive break-glass request owns the Slack channel'
          : 'NOTIFY: Slack not routed for this verdict'
    );
  }

  // If a remote surface failed, record it in the local summary too, so the
  // failure is visible as "notification failed" rather than a silently missing
  // channel. Best effort — never throws.
  if (failures.length > 0 && routing.summary && performed.summary) {
    try {
      await writeStepSummary(
        `\n> ⚠️ **Notification delivery incomplete:** ${failures.join('; ')}. ` +
          'The findings above are complete; only remote delivery failed.\n',
        { summaryPath, appendImpl }
      );
    } catch {
      // The primary summary already landed; a footer failure is not worth crashing.
    }
  }

  return { ...performed, failures };
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

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const gate = JSON.parse(await readFile(options.gate, 'utf8'));
  const context = {
    repository: process.env.GITHUB_REPOSITORY,
    sha: process.env.GITHUB_SHA,
    prNumber: process.env.PR_NUMBER || null,
    runUrl:
      process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
        ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
        : null,
    // Per-repo "reproduce this locally" commands. Unset falls back to direct
    // scanner invocations that hold in any repo, never to this repo's Makefile.
    reproduceCommands: resolveReproduceCommands(process.env.SECURITY_REPRODUCE_COMMANDS)
  };
  // gate_mode drives Slack suppression; a repo still in log-only pages no one.
  const mode = (process.env.GATE_MODE || options.mode || 'enforce').toLowerCase();

  const performed = await dispatch({
    gate,
    context,
    mode,
    slackUrl: process.env.SECURITY_NOTIFY_SLACK_URL,
    token: process.env.GITHUB_TOKEN,
    summaryPath: process.env.GITHUB_STEP_SUMMARY
  });

  console.log(
    `Notified verdict=${performed.verdict} slack=${performed.slack} pr=${performed.prComment} summary=${performed.summary}`
  );
  // Mark the step failed in its own log when a remote surface could not be
  // delivered. The gate's verdict is decided by a different step, so this never
  // masks (or manufactures) the pass/fail signal; with continue-on-error on the
  // workflow step it does not fail the job — it just makes the delivery gap
  // legible to anyone reading the run.
  if (performed.failures.length > 0) {
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  await main();
}
