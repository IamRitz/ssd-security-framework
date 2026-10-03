// Posts the break-glass audit comment to the pull request, directly via fetch
// with the fine-grained PAT. Replaces the n8n HTTP Request node.
export function createGithubClient({ token, fetchImpl = globalThis.fetch }) {
  return {
    async postComment(repository, pullRequest, body) {
      const url = `https://api.github.com/repos/${repository}/issues/${pullRequest}/comments`;
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28',
          'content-type': 'application/json'
        },
        body: JSON.stringify({ body }),
        signal: globalThis.AbortSignal.timeout(15_000)
      });
      if (!response.ok) {
        throw new Error(`GitHub comment failed: HTTP ${response.status}`);
      }
      return response.json();
    }
  };
}
