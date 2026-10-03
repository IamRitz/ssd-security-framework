// Thin Slack Web API client — calls chat.postMessage / chat.update directly via
// fetch with the Bot Token, and posts ephemeral follow-ups to an interaction's
// response_url. Replaces the n8n HTTP Request nodes.
export function createSlackClient({ botToken, fetchImpl = globalThis.fetch }) {
  async function call(method, body) {
    const response = await fetchImpl(`https://slack.com/api/${method}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${botToken}`,
        'content-type': 'application/json; charset=utf-8'
      },
      body: JSON.stringify(body),
      signal: globalThis.AbortSignal.timeout(15_000)
    });
    const result = await response.json();
    if (!result.ok) {
      throw new Error(`Slack ${method} failed: ${result.error || `HTTP ${response.status}`}`);
    }
    return result;
  }

  return {
    postMessage: (message) => call('chat.postMessage', message),
    update: (message) => call('chat.update', message),
    // response_url is a pre-signed Slack URL; it takes no auth header.
    respond: async (responseUrl, message) => {
      await fetchImpl(responseUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(message),
        signal: globalThis.AbortSignal.timeout(15_000)
      });
    }
  };
}
