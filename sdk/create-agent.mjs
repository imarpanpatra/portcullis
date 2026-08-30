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

// The SDK exposes list() for skills and connectors but not create(), so these two
// go over plain HTTP. PUT is create-or-replace, which keeps this script safe to
// re-run.
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
    name: CONNECTOR_NAME,
    type: "remote",
    url,
    description:
      "npm registry, download statistics, and OSV advisories. Read-only, no credentials.",
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
    name: SKILL_NAME,
    type: "git",
    url: repo,
    ref,
    path: `skills/${SKILL_NAME}`,
    description:
      "Decide whether a third-party npm package is safe to admit into a repository: unpack " +
      "the published tarball in the sandbox, read what actually ships, weigh it against " +
      "registry signals, and reach a verdict backed by evidence.",
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

  const { data } = await client.models.list();
  const available = data?.data ?? [];
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
 * The GitHub connector is the one piece this script cannot set up. It is an OAuth
 * catalog entry, so a person has to authorise it. Better to say so plainly than to
 * create an agent whose write path silently does not exist.
 */
async function checkGithubConnector(required) {
  if (!required) return true;
  const { data } = await client.mcpServers.list();
  const names = (data?.data ?? []).map((server) => server.name);
  if (names.includes("github")) return true;

  console.warn("\n  WARNING: no 'github' connector is configured on this server.");
  console.warn("  The audit will run, but the agent will have nothing to open a pull request");
  console.warn("  with. Connect it under Settings -> Connectors (it uses OAuth, so it has to");
  console.warn("  be authorised by a person) and re-run this script.\n");
  return false;
}

async function findExisting(name) {
  const { data } = await client.agents.list();
  return (data?.data ?? []).find((agent) => agent.name === name) ?? null;
}

async function main() {
  const manifest = JSON.parse(fs.readFileSync(SPEC_PATH, "utf8"));

  const connectorUrl = await registerConnector();
  console.log(`connector : ${CONNECTOR_NAME} -> ${connectorUrl}`);

  const skillSource = await registerSkill();
  console.log(`skill     : ${SKILL_NAME} -> ${skillSource}`);

  manifest.model.name = await resolveModel(manifest.model?.name);

  const wantsGithub = manifest.mcp_servers.some((server) => server.name === "github");
  await checkGithubConnector(wantsGithub);

  const gated = manifest.mcp_servers.flatMap((server) => server.require_approval_for_tools ?? []);
  console.log(`\nAgent   : ${AGENT_NAME}`);
  console.log(`Model   : ${manifest.model.name}`);
  console.log(`Tools   : ${manifest.mcp_servers.map((s) => s.name).join(", ")}`);
  console.log(`Skills  : ${(manifest.skills ?? []).map((s) => s.name).join(", ") || "none"}`);
  console.log(`Sandbox : ${manifest.config?.sandbox?.enabled ? "enabled" : "disabled"}`);
  console.log(`Gated   : ${gated.join(", ")}\n`);

  const existing = await findExisting(AGENT_NAME);
  if (existing) {
    await client.agents.update(existing.id, { manifest });
    console.log(`Updated existing agent ${existing.id}`);
  } else {
    const { data } = await client.agents.create({ name: AGENT_NAME, manifest });
    console.log(`Created agent ${data?.data?.id ?? data?.id ?? "(id not returned)"}`);
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
