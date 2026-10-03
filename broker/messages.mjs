// Slack Block Kit builders — the same message shape the n8n workflow produced,
// so the channel experience is unchanged after the migration.

export function buildApprovalMessage(request, channel) {
  const lines = request.findings.map(
    (finding) => `- ${finding.policyRule}: ${finding.id} - ${finding.reason}`
  );
  return {
    channel,
    text: 'Break-glass security exception requested',
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: 'Break-glass security exception requested' } },
      { type: 'section', text: { type: 'mrkdwn', text: lines.join('\n').slice(0, 2900) } },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Repository*\n${request.context.repository}` },
          { type: 'mrkdwn', text: `*Pull request*\n#${request.context.pullRequest}` },
          { type: 'mrkdwn', text: `*Commit*\n${String(request.context.commitSha).slice(0, 12)}` },
          { type: 'mrkdwn', text: `*Expires*\n${request.expiresAt}` }
        ]
      },
      {
        type: 'actions',
        block_id: `breakglass:${request.requestId}`,
        elements: [
          {
            type: 'button',
            style: 'primary',
            text: { type: 'plain_text', text: 'Approve' },
            action_id: `breakglass:${request.requestId}:approve`,
            value: `breakglass:${request.requestId}:approve`
          },
          {
            type: 'button',
            style: 'danger',
            text: { type: 'plain_text', text: 'Deny' },
            action_id: `breakglass:${request.requestId}:deny`,
            value: `breakglass:${request.requestId}:deny`
          }
        ]
      }
    ]
  };
}

// The replacement message posted via chat.update once a decision is finalized —
// the buttons are gone (the message is rendered read-only).
export function buildDecisionUpdate(request) {
  const decision = request.status;
  const findingText = request.findings.map((finding) => `${finding.policyRule}: ${finding.id}`).join('; ');
  const approver = request.approver || {};
  return {
    channel: request.slack.channel,
    ts: request.slack.ts,
    text: `Break-glass ${decision}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Break-glass ${decision.toUpperCase()}* by <@${approver.id}>\n${findingText}`
        }
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `Decided ${request.decidedAt} - gate \`${String(request.gateDigest).slice(0, 12)}\``
          }
        ]
      }
    ]
  };
}

export function ephemeral(text) {
  return { response_type: 'ephemeral', replace_original: false, text };
}
