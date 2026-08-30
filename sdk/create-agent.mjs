// Register everything Portcullis needs on a running TrueForge server: the custom
// MCP connector, the audit skill, and the agent itself.
//
// The agent spec lives in agent/portcullis.agent.json. It is created here rather
// than in the chat UI because the UI does not expose require_approval_for_tools,
// and that field is the whole point of this agent.
//
// The connector and the skill are registered here for a duller reason: an agent
// spec only *references* them by name. Referencing a skill that the server has
// never been told about gets you an agent that cannot load its own procedure, so
// the reference and the registration have to travel together.
//
//   node create-agent.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TrueForge } from "@truefoundry/trueforge-sdk";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC_PATH = path.join(HERE, "..", "agent", "portcullis.agent.json");
const AGENT_NAME = "portcullis";
const SKILL_NAME = "supply-chain-audit";
const CONNECTOR_NAME = "portcullis";
const PLACEHOLDER = "REPLACE_WITH_YOUR_MODEL";

const baseUrl = (process.env.TRUEFORGE_BASE_URL ?? "http://localhost:8790").replace(/\/$/, "");
const token = process.env.TRUEFORGE_TOKEN;

const client = new TrueForge({ baseUrl, token, timeoutInSeconds: 120 });

// The SDK's list() calls resolve to { data: [...] } -- the array sits directly on
// `data`, not nested under a second `data`. Getting that wrong does not throw; it
// silently yields an empty list, which reads as "nothing is configured" and is a
// miserable thing to debug. This normalises either shape so the mistake cannot
// come back.
function items(response) {
  const payload = response?.data;
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.data)) return payload.data;
  return [];
}

// The SDK exposes list() for skills and connectors but not create(), so these two
// go over plain HTTP. PUT is create-or-replace, which keeps this script safe to
// re-run. Both endpoints expect the resource wrapped in `manifest`, the same shape
// agents.create takes.
async function put(resourcePath, body) {
  const response = await fetch(`${baseUrl}${resourcePath}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`PUT ${resourcePath} -> ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function registerConnector() {
  const url = process.env.PORTCULLIS_MCP_URL ?? "http://localhost:8941/mcp";
  await put("/api/v1/settings/mcp-servers", {
    manifest: {
      name: CONNECTOR_NAME,
      type: "remote",
      url,
      description:
        "npm registry, download statistics, and OSV advisories. Read-only, no credentials.",
    },
  });
  return url;
}

async function registerSkill() {
  // Git-backed: TrueForge clones this directory into the sandbox when the agent
  // decides the skill is relevant. It has to be a URL the server can reach, which
  // is why it points at the published repository rather than the local checkout.
  const repo = process.env.PORTCULLIS_SKILL_REPO ?? "https://github.com/imarpanpatra/portcullis";
  const ref = process.env.PORTCULLIS_SKILL_REF ?? "main";
  await put("/api/v1/settings/skills", {
    manifest: {
      name: SKILL_NAME,
      type: "git",
      url: repo,
      ref,
      path: `skills/${SKILL_NAME}`,
      description:
        "Decide whether a third-party npm package is safe to admit into a repository: unpack " +
        "the published tarball in the sandbox, read what actually ships, weigh it against " +
        "registry signals, and reach a verdict backed by evidence.",
    },
  });
  return `${repo}@${ref}`;
}

/**
 * Work out which model to run on. An explicit choice wins; otherwise ask the
 * server what it has, so that someone running this project does not need to know
 * which provider happened to be configured when it was written.
 */
async function resolveModel(specModel) {
  if (process.env.PORTCULLIS_MODEL) return process.env.PORTCULLIS_MODEL;
  if (specModel && specModel !== PLACEHOLDER) return specModel;

  const available = items(await client.models.list());
  if (available.length === 0) {
    throw new Error(
      `No models are configured on ${baseUrl}. Open Settings -> Models, add a provider, ` +
        "then run this again (or set PORTCULLIS_MODEL to a fully qualified name).",
    );
  }
  const chosen = available[0].name;
  console.log(`No model specified; using the first one configured: ${chosen}`);
  console.log(`   available: ${available.map((m) => m.name).join(", ")}`);
  return chosen;
}

/**
 * The GitHub connector is the one piece this script cannot set up: it authenticates
 * with a personal access token, so a person has to paste one in under
 * Settings -> Connectors.
 *
 * A missing connector is fatal by default. The server rejects the agent anyway, but
 * the better reason is that an agent quietly created without its write path still
 * audits packages perfectly well -- it simply can never open a pull request, and
 * that is not something to discover halfway through a demo.
 *
 * --skip-missing-connectors opts into that reduced agent deliberately, which is
 * useful for exercising the read-only half before a token exists.
 */
async function resolveConnectors(manifest, allowSkip) {
  const configured = new Set(items(await client.mcpServers.list()).map((s) => s.name));
  const missing = manifest.mcp_servers.filter((server) => !configured.has(server.name));

  if (missing.length === 0) return manifest;
  const names = missing.map((server) => server.name).join(", ");

  if (!allowSkip) {
    throw new Error(
      [
        `Referenced by the agent but not configured on the server: ${names}.`,
        "",
        "Add them under Settings -> Connectors. GitHub authenticates with a personal",
        "access token, pasted as an Authorization header.",
        "",
        "To create a reduced agent without them on purpose, pass --skip-missing-connectors.",
        "That agent can audit packages but can never open a pull request.",
      ].join("\n"),
    );
  }

  console.warn(`\n  WARNING: creating a REDUCED agent, without: ${names}`);
  console.warn("  It can audit packages, but has no way to open a pull request, so the");
  console.warn("  approval gate is unreachable. Do not record a demo with this agent.\n");

  return {
    ...manifest,
    mcp_servers: manifest.mcp_servers.filter((server) => configured.has(server.name)),
  };
}

async function findExisting(name) {
  return items(await client.agents.list()).find((agent) => agent.name === name) ?? null;
}

async function main() {
  const manifest = JSON.parse(fs.readFileSync(SPEC_PATH, "utf8"));

  const connectorUrl = await registerConnector();
  console.log(`connector : ${CONNECTOR_NAME} -> ${connectorUrl}`);

  const skillSource = await registerSkill();
  console.log(`skill     : ${SKILL_NAME} -> ${skillSource}`);

  manifest.model.name = await resolveModel(manifest.model?.name);

  const allowSkip = process.argv.includes("--skip-missing-connectors");
  const resolved = await resolveConnectors(manifest, allowSkip);

  const gated = resolved.mcp_servers.flatMap((server) => server.require_approval_for_tools ?? []);
  console.log(`\nAgent   : ${AGENT_NAME}`);
  console.log(`Model   : ${resolved.model.name}`);
  console.log(`Tools   : ${resolved.mcp_servers.map((s) => s.name).join(", ")}`);
  console.log(`Skills  : ${(resolved.skills ?? []).map((s) => s.name).join(", ") || "none"}`);
  console.log(`Sandbox : ${resolved.config?.sandbox?.enabled ? "enabled" : "disabled"}`);
  console.log(`Gated   : ${gated.join(", ") || "nothing (no write connector attached)"}\n`);

  const existing = await findExisting(AGENT_NAME);
  if (existing) {
    await client.agents.update(existing.id, { manifest: resolved });
    console.log(`Updated existing agent ${existing.id}`);
  } else {
    const { data } = await client.agents.create({ name: AGENT_NAME, manifest: resolved });
    console.log(`Created agent ${data?.id ?? data?.data?.id ?? "(id not returned)"}`);
  }

  console.log("\nRun an audit with:  node audit.mjs <package> [--repo owner/name]");
}

main().catch((error) => {
  // A connection refused here almost always means the server is not running, and
  // saying so is more use than a stack trace about ECONNREFUSED.
  if (String(error?.message ?? "").includes("fetch failed")) {
    console.error(`Could not reach a TrueForge server at ${baseUrl}.`);
    console.error("Start one with:  npx @truefoundry/trueforge@latest");
  } else {
    console.error(error?.message ?? error);
  }
  process.exit(1);
});
