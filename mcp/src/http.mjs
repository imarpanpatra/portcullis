// Shared HTTP helpers. Every outbound call from this server is an unauthenticated
// GET or POST against a public registry, so the only things worth centralising are
// the timeout, the user agent, and turning a failure into something the agent can
// reason about instead of an exception it cannot see.

const DEFAULT_TIMEOUT_MS = 10_000;
const USER_AGENT = "portcullis-mcp (+https://github.com/imarpanpatra/portcullis)";

export class UpstreamError extends Error {
  constructor(message, { status = null, url = null } = {}) {
    super(message);
    this.name = "UpstreamError";
    this.status = status;
    this.url = url;
  }
}

async function request(url, init = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      headers: { "user-agent": USER_AGENT, ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    const reason = cause?.name === "TimeoutError" ? `timed out after ${timeoutMs}ms` : cause?.message;
    throw new UpstreamError(`Request to ${url} failed: ${reason}`, { url });
  }

  if (!response.ok) {
    throw new UpstreamError(`Request to ${url} returned ${response.status}`, {
      status: response.status,
      url,
    });
  }
  return response;
}

export async function getJson(url, { timeoutMs, headers } = {}) {
  const response = await request(url, { headers }, timeoutMs);
  return response.json();
}

export async function postJson(url, body, { timeoutMs, headers } = {}) {
  const response = await request(
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json", ...(headers ?? {}) },
      body: JSON.stringify(body),
    },
    timeoutMs,
  );
  return response.json();
}
