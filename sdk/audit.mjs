// Run one audit against the Portcullis agent, from the terminal.
//
// The chat UI can do this too. What this script exists to show is the pause: when
// the agent decides to write to a repository, the turn stops, the harness hands
// back the exact tool call it wants to make, and nothing continues until a person
// answers. Approving is not a formality the client can skip -- resuming requires
// sending a user.tool_approval event, so a client that ignores the pause simply
// never gets a pull request.
//
//   node audit.mjs express
//   node audit.mjs left-pad --repo imarpanpatra/some-project
//   node audit.mjs lodash --deny        (answer no without being asked, for demos)

import readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { TrueForge, isEventDelta, mergeEventDelta } from "@truefoundry/trueforge-sdk";

const AGENT_NAME = "portcullis";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--repo") flags.repo = argv[++i];
    else if (argv[i] === "--deny") flags.deny = true;
    else if (argv[i] === "--yes") flags.yes = true;
    else positional.push(argv[i]);
  }
  return { pkg: positional[0], ...flags };
}

const args = parseArgs(process.argv.slice(2));
if (!args.pkg) {
  console.error("usage: node audit.mjs <package> [--repo owner/name] [--deny] [--yes]");
  process.exit(1);
}

const client = new TrueForge({
  baseUrl: process.env.TRUEFORGE_BASE_URL ?? "http://localhost:8790",
  token: process.env.TRUEFORGE_TOKEN,
  timeoutInSeconds: 900, // audits unpack tarballs in a sandbox; they are not quick
});

const rule = (label) => console.log(`\n${"-".repeat(72)}\n${label}\n${"-".repeat(72)}`);

/**
 * Stream one turn, printing the agent's reply as it arrives and keeping an index of
 * every event by id. The index is what makes a pause actionable: an approval request
 * names a tool call, and the call itself lives on an earlier model.message.
 */
async function runTurn(sessionId, input) {
  const events = new Map();
  const pendingApprovals = [];
  const threads = new Map();
  let printedThreadNote = false;

  const stream = await client.sessions.createTurnStream(sessionId, { input });

  for await (const { data: event } of stream.withMetadata()) {
    if (isEventDelta(event)) {
      const base = events.get(event.id);
      if (base) mergeEventDelta(base, event);
      if (event.threadId === "main" && event.content) stdout.write(event.content);
      continue;
    }

    events.set(event.id, event);

    switch (event.type) {
      case "thread.created":
        threads.set(event.threadId, event.title);
        console.log(`\n  [subagent] ${event.title ?? event.threadId}`);
        break;
      case "model.message":
        for (const call of event.toolCalls ?? []) {
          console.log(`\n  -> ${call.toolInfo?.name ?? call.function?.name}`);
        }
        break;
      case "tool.approval_required":
        pendingApprovals.push(event);
        break;
      case "turn.done":
        if (!printedThreadNote && threads.size) {
          printedThreadNote = true;
        }
        break;
      default:
        break;
    }
  }

  return { events, pendingApprovals };
}

/** Turn a pending approval into the concrete calls it is asking about. */
function describePending(events, pending) {
  const described = [];
  for (const ref of pending.toolCalls ?? []) {
    const source = events.get(ref.sourceEventId);
    if (source?.type !== "model.message") continue;
    const call = (source.toolCalls ?? []).find((tc) => tc.id === ref.id);
    if (!call) continue;
    described.push({
      threadId: pending.threadId,
      id: ref.id,
      name: call.toolInfo?.name ?? call.function?.name ?? "(unnamed tool)",
      arguments: call.function?.arguments ?? "{}",
    });
  }
  return described;
}

async function askApproval(calls) {
  if (args.deny) return { status: "deny", reason: "denied by the operator" };
  if (args.yes) return { status: "allow" };

  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const answer = (await rl.question(`\nAllow ${calls.length} call(s)? [y/N] `)).trim().toLowerCase();
    return answer === "y" || answer === "yes"
      ? { status: "allow" }
      : { status: "deny", reason: "denied by the operator" };
  } finally {
    rl.close();
  }
}

async function main() {
  const question = args.repo
    ? `Can I add the npm package "${args.pkg}" to ${args.repo}? Audit it first, and if it passes, open the pull request that adds it.`
    : `Audit the npm package "${args.pkg}" and tell me whether it is safe to add to a project.`;

  const { data: session } = await client.sessions.create({ agent: { name: AGENT_NAME } });
  rule(`session ${session.id}  |  agent ${AGENT_NAME}  |  package ${args.pkg}`);

  let input = [{ type: "user.message", content: question }];

  // Each pause ends a turn. Resuming means opening a new turn carrying the
  // decisions, so this loop runs until the agent finishes without asking.
  for (let round = 0; round < 8; round += 1) {
    const { events, pendingApprovals } = await runTurn(session.id, input);

    if (pendingApprovals.length === 0) {
      rule("done");
      return;
    }

    const calls = pendingApprovals.flatMap((pending) => describePending(events, pending));

    rule("PAUSED - the agent is asking permission before it writes");
    for (const call of calls) {
      console.log(`\ntool: ${call.name}`);
      let parsed;
      try {
        parsed = JSON.parse(call.arguments);
      } catch {
        parsed = call.arguments;
      }
      console.log(`args: ${JSON.stringify(parsed, null, 2)}`);
    }

    const decision = await askApproval(calls);
    console.log(`\n${decision.status === "allow" ? "APPROVED" : "DENIED"} - resuming\n`);

    input = calls.map((call) => ({
      type: "user.tool_approval",
      threadId: call.threadId,
      toolCallId: call.id,
      approval: decision,
    }));
  }

  rule("stopped after 8 rounds of pauses");
}

main().catch((error) => {
  const message = String(error?.message ?? error);
  if (message.includes("fetch failed")) {
    console.error("\nCould not reach TrueForge. Start it with: npx @truefoundry/trueforge@latest");
  } else if (message.includes("404")) {
    console.error(`\nNo agent named "${AGENT_NAME}". Run: node create-agent.mjs`);
  } else {
    console.error(`\n${message}`);
  }
  process.exit(1);
});
