// Register the Portcullis agent with a running TrueForge server.
//
// The agent spec lives in agent/portcullis.agent.json. It is created here rather
// than in the chat UI because the UI does not expose require_approval_for_tools,
// and that field is the whole point of this agent.
//
//   node create-agent.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TrueForge } from "@truefoundry/trueforge-sdk";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC_PATH = path.join(HERE, "..", "agent", "portcullis.agent.json");
const AGENT_NAME = "portcullis";
const PLACEHOLDER = "REPLACE_WITH_YOUR_MODEL";

const baseUrl = process.env.TRUEFORGE_BASE_URL ?? "http://localhost:8790";
const client = new TrueForge({
  baseUrl,
  token: process.env.TRUEFORGE_TOKEN,
  timeoutInSeconds: 120,
});

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
  console.log(`   (set PORTCULLIS_MODEL to override. Available: ${available.map((m) => m.name).join(", ")})`);
  return chosen;
}

async function findExisting(name) {
  const { data } = await client.agents.list();
  return (data?.data ?? []).find((agent) => agent.name === name) ?? null;
}

async function main() {
  const manifest = JSON.parse(fs.readFileSync(SPEC_PATH, "utf8"));
  manifest.model.name = await resolveModel(manifest.model?.name);

  const connectors = manifest.mcp_servers.map((server) => server.name);
  const gated = manifest.mcp_servers.flatMap((server) => server.require_approval_for_tools ?? []);

  console.log(`\nAgent   : ${AGENT_NAME}`);
  console.log(`Model   : ${manifest.model.name}`);
  console.log(`Tools   : ${connectors.join(", ")}`);
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
