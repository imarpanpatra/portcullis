// Run one audit against the Portcullis agent, from the terminal.
//
// The chat UI can do this too. What this script exists to show is the two places a
// turn stops and waits for a person:
//
//   tool.approval_required   the agent wants to write to a repository
//   tool.response_required   the agent is asking a question it should not guess
//
// Both end the turn. Resuming means opening a new one carrying the decision, so a
// client that ignores either simply never gets a result -- the gate lives in the
// harness, not in the politeness of the client.
//
// A turn also runs on the server rather than in this process, so a dropped stream
// is reattached to rather than restarted, and a session can be rejoined later --
// or by a second client while the first is still working.
//
//   node audit.mjs express
//   node audit.mjs express chalk ms          (one subagent per package, in parallel)
//   node audit.mjs left-pad --repo imarpanpatra/portcullis-demo
//   node audit.mjs lodash --deny             (refuse the write without being asked)
//   node audit.mjs axios --session <id>      (rejoin a session, or a running turn)

import readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { TrueForge, isEventDelta, mergeEventDelta } from "@truefoundry/trueforge-sdk";

const AGENT_NAME = "portcullis";
const MAX_ROUNDS = 8;

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--repo") flags.repo = argv[++i];
    else if (argv[i] === "--session") flags.session = argv[++i];
    else if (argv[i] === "--deny") flags.deny = true;
    else positional.push(argv[i]);
  }
  return { packages: positional, ...flags };
}

const args = parseArgs(process.argv.slice(2));
if (args.packages.length === 0) {
  console.error("usage: node audit.mjs <package...> [--repo owner/name] [--session id] [--deny]");
  console.error("");
  console.error("  node audit.mjs express                     audit one package");
  console.error("  node audit.mjs express chalk ms            audit several, in parallel");
  console.error("  node audit.mjs express --session sess-abc  continue an earlier session");
  console.error("");
  console.error("There is deliberately no --yes. See the note at the bottom of this file.");
  process.exit(1);
}

const client = new TrueForge({
  baseUrl: process.env.TRUEFORGE_BASE_URL ?? "http://localhost:8790",
  token: process.env.TRUEFORGE_TOKEN,
  timeoutInSeconds: 900, // audits unpack tarballs in a sandbox; they are not quick
});

const rule = (label) => console.log(`\n${"-".repeat(72)}\n${label}\n${"-".repeat(72)}`);

// Answers are read from a queue rather than with readline.question().
//
// readline drains its input to EOF and drops whatever nobody asked for yet, so
// piping answers in works for the first prompt and then fails with "readline was
// closed" -- which looks like a crash and is really just a lost buffer. Queueing
// every line as it arrives means a run can be answered interactively or from a
// script, without the tool having to offer a blanket approve-everything flag.
const pending = [];
const waiting = [];
let inputClosed = false;

const reader = readline.createInterface({ input: stdin, crlfDelay: Infinity });
reader.on("line", (line) => {
  const waiter = waiting.shift();
  if (waiter) waiter(line);
  else pending.push(line);
});
reader.on("close", () => {
  inputClosed = true;
  while (waiting.length) waiting.shift()(null);
});

/** Resolves to the next line, or null when there is nobody left to answer. */
async function ask(prompt) {
  stdout.write(prompt);
  if (pending.length) return pending.shift().trim();
  if (inputClosed) return null;
  return new Promise((resolve) => waiting.push((line) => resolve(line?.trim() ?? null)));
}

function closePrompt() {
  reader.close();
}

/**
 * Stream one turn, printing the agent's reply as it arrives and keeping an index of
 * every event by id. The index is what makes a pause actionable: a pause names a
 * tool call, and the call itself lives on an earlier model.message.
 */
const MAX_RECONNECTS = 3;

/**
 * Run a turn and follow it to the end.
 *
 * With `input`, a new turn is created. With `attachTo`, an existing turn already
 * running on the server is joined instead -- which is what resuming a session has
 * to do, because asking the question again would start a second audit alongside
 * the first.
 */
async function runTurn(sessionId, { input = null, attachTo = null } = {}) {
  const events = new Map();
  const pendingApprovals = [];
  const pendingQuestions = [];
  const threads = new Map();
  let turnId = null;
  let done = false;

  // Consume one stream until it ends, recording what we learn. Returns normally
  // when the turn finishes and throws if the connection breaks mid-flight, which
  // the caller treats as something to reconnect to rather than something fatal.
  const consume = async (stream) => {
    for await (const { data: event } of stream.withMetadata()) {
      if (isEventDelta(event)) {
        const base = events.get(event.id);
        if (base) mergeEventDelta(base, event);
        if (event.threadId === "main" && event.content) stdout.write(event.content);
        continue;
      }

      events.set(event.id, event);

      switch (event.type) {
        case "turn.created":
          turnId = event.turnId ?? event.id;
          break;
        case "thread.created":
          threads.set(event.threadId, event.title ?? event.threadId);
          console.log(`\n  [subagent ${threads.size}] ${event.title ?? event.threadId}`);
          break;
        case "thread.done":
          console.log(`\n  [subagent done] ${threads.get(event.threadId) ?? event.threadId}`);
          break;
        case "model.message":
          for (const call of event.toolCalls ?? []) {
            const where = event.threadId === "main" ? "" : "     ";
            console.log(`\n  ${where}-> ${call.toolInfo?.name ?? call.function?.name}`);
          }
          break;
        case "tool.approval_required":
          pendingApprovals.push(event);
          break;
        case "tool.response_required":
          pendingQuestions.push(event);
          break;
        case "turn.done":
          done = true;
          break;
        default:
          break;
      }
    }
  };

  // The first stream has to be guarded too. Letting an error escape here would
  // skip the reconnect loop entirely -- and a dropped connection is precisely the
  // case the loop exists for, so the one failure it was written to survive would
  // have been the one that got past it.
  try {
    if (attachTo) {
      turnId = attachTo;
      await consume(await client.sessions.subscribeToTurn(sessionId, attachTo));
    } else {
      await consume(await client.sessions.createTurnStream(sessionId, { input }));
    }
  } catch (error) {
    console.log(`\n  [stream failed: ${error?.message ?? error}]`);
  }

  // The turn runs on the server, not in this process. If the stream drops, the
  // work carries on without us, so the right response is to attach to it again
  // rather than to start over -- restarting would re-run tool calls that already
  // happened. subscribeToTurn picks the same turn back up.
  for (let attempt = 1; !done && turnId && attempt <= MAX_RECONNECTS; attempt += 1) {
    console.log(`\n  [turn did not finish on this stream; reattaching (${attempt}/${MAX_RECONNECTS})]`);
    try {
      await consume(await client.sessions.subscribeToTurn(sessionId, turnId));
    } catch (error) {
      console.log(`  [reattach failed: ${error?.message ?? error}]`);
    }
  }

  if (!done && turnId) {
    console.log(
      `\n  [gave up reattaching. The turn is still on the server; rejoin it with --session ${sessionId}]`,
    );
  }

  if (threads.size) console.log(`\n  (${threads.size} subagent(s) ran in this turn)`);

  return { events, pendingApprovals, pendingQuestions };
}

/** Resolve a pending event's refs into the concrete calls they point at. */
function describePending(events, pending) {
  const described = [];
  for (const ref of pending.toolCalls ?? []) {
    const source = events.get(ref.sourceEventId);
    if (source?.type !== "model.message") continue;
    const call = (source.toolCalls ?? []).find((tc) => tc.id === ref.id);
    if (!call) continue;

    let parsed;
    try {
      parsed = JSON.parse(call.function?.arguments ?? "{}");
    } catch {
      parsed = call.function?.arguments ?? {};
    }
    described.push({
      threadId: pending.threadId,
      id: ref.id,
      name: call.toolInfo?.name ?? call.function?.name ?? "(unnamed tool)",
      arguments: parsed,
    });
  }
  return described;
}

/**
 * The agent asked something it should not guess at -- most often "did you mean
 * express?" when the package named looks like a typo of a far more popular one.
 * Without this the turn ends here and the audit never reaches a verdict.
 */
async function answerQuestions(calls) {
  const answers = [];
  for (const call of calls) {
    const question = call.arguments?.question ?? "(the agent asked a question)";
    const options = Array.isArray(call.arguments?.options) ? call.arguments.options : [];

    console.log(`\n${question}`);
    options.forEach((option, index) => {
      const label = typeof option === "string" ? option : option?.label ?? JSON.stringify(option);
      console.log(`  ${index + 1}. ${label}`);
    });

    const reply = await ask(options.length ? "\nchoose a number, or type an answer: " : "\nanswer: ");
    if (reply === null) {
      throw new Error(
        "The agent asked a question and stdin ended before an answer arrived. " +
          "Re-run with the answer piped in, or answer it interactively.",
      );
    }
    const chosen = options[Number(reply) - 1];
    const content =
      chosen === undefined
        ? reply
        : typeof chosen === "string"
          ? chosen
          : chosen?.label ?? JSON.stringify(chosen);

    answers.push({
      type: "user.tool_response",
      threadId: call.threadId,
      toolCallId: call.id,
      content,
    });
  }
  return answers;
}

async function decideApprovals(calls) {
  rule("PAUSED - the agent is asking permission before it writes");
  for (const call of calls) {
    console.log(`\ntool: ${call.name}`);
    console.log(`args: ${JSON.stringify(call.arguments, null, 2)}`);
  }

  let decision;
  if (args.deny) {
    decision = { status: "deny", reason: "denied by the operator" };
  } else {
    const answer = await ask(`\nAllow ${calls.length} call(s)? [y/N] `);
    // A null answer means stdin ended without one. Fail closed: no operator is a
    // reason to refuse, never a reason to proceed. The prompt defaults to no for
    // the same reason -- an accidental Enter must not authorise a write.
    decision = answer?.toLowerCase().startsWith("y")
      ? { status: "allow" }
      : { status: "deny", reason: answer === null ? "no operator available to approve" : "denied by the operator" };
  }

  console.log(`\n${decision.status === "allow" ? "APPROVED" : "DENIED"} - resuming\n`);
  return calls.map((call) => ({
    type: "user.tool_approval",
    threadId: call.threadId,
    toolCallId: call.id,
    approval: decision,
  }));
}

function buildQuestion() {
  const many = args.packages.length > 1;
  const list = args.packages.map((name) => `"${name}"`).join(", ");

  if (args.repo) {
    return many
      ? `Can I add these npm packages to ${args.repo}: ${list}? Audit each one -- in parallel, one subagent per package -- and give a verdict for each. Then open a pull request adding the ones that pass.`
      : `Can I add the npm package ${list} to ${args.repo}? Audit it first, and if it passes, open the pull request that adds it.`;
  }
  return many
    ? `Audit these npm packages and tell me whether each is safe to add: ${list}. Do them in parallel, one subagent per package, and give a verdict for each.`
    : `Audit the npm package ${list} and tell me whether it is safe to add to a project.`;
}

/**
 * Reuse a session when one is named, rather than always starting fresh.
 *
 * Sessions hold their context on the server, so a resumed one already knows what
 * was audited and decided earlier -- the client going away does not end the
 * conversation. That is worth exercising rather than assuming: an agent that only
 * works while one terminal stays open is a script with extra steps.
 */
async function openSession() {
  if (!args.session) {
    const { data: created } = await client.sessions.create({ agent: { name: AGENT_NAME } });
    return { session: created, running: null };
  }

  const { data } = await client.sessions.get(args.session);
  const existing = data?.id ? data : (data?.data ?? { id: args.session });

  const turns = [];
  for await (const turn of await client.sessions.listTurns(existing.id)) turns.push(turn);

  // A session can be resumed while a turn is still going. Submitting the question
  // again in that state would run a *second* audit beside the first -- repeating
  // tool calls, and for an agent that opens pull requests, potentially producing a
  // second branch and a second PR from one approval. Recovery means rejoining the
  // turn that is already running, not starting another one.
  const last = turns[turns.length - 1];
  const running = last?.state?.status === "running" ? last : null;

  console.log(`\nresuming session ${existing.id} — ${turns.length} earlier turn(s) already in it`);
  if (running) {
    console.log(`  a turn is still running (${running.id}); rejoining it rather than asking again`);
  }
  return { session: existing, running };
}

async function main() {
  const question = buildQuestion();
  const { session, running } = await openSession();

  const label = args.packages.length > 1 ? "packages" : "package";
  rule(`session ${session.id}  |  agent ${AGENT_NAME}  |  ${label} ${args.packages.join(", ")}`);
  console.log(`continue this session later:  node audit.mjs <package> --session ${session.id}\n`);

  // Rejoining an in-flight turn means observing the work already under way, so the
  // question is not asked again. It is asked only once that turn has finished.
  let attachTo = running?.id ?? null;
  let input = attachTo ? null : [{ type: "user.message", content: question }];

  // Every pause ends a turn, so continuing means opening a new one. This runs until
  // the agent finishes a turn without asking for anything. A rejoined turn is
  // observed first; the question only goes in once that turn has come to rest.
  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const { events, pendingApprovals, pendingQuestions } = await runTurn(session.id, {
      input,
      attachTo,
    });

    if (pendingApprovals.length === 0 && pendingQuestions.length === 0) {
      // A rejoined turn finishing without a pause means the work we came back for
      // is done. Ask the question now, in a turn of its own, rather than treating
      // the run as over.
      if (attachTo) {
        attachTo = null;
        input = [{ type: "user.message", content: question }];
        continue;
      }
      closePrompt();
      rule("done");
      return;
    }

    // Check the budget before asking, not after. Collecting an approval and then
    // falling out of the loop without submitting it would print "APPROVED" while
    // the write never happened -- worse than refusing, because the operator is
    // told the opposite of the truth. If there is no round left to spend, say so
    // and ask for nothing.
    if (round === MAX_ROUNDS - 1) {
      closePrompt();
      rule(`stopped after ${MAX_ROUNDS} rounds of pauses; nothing further was submitted`);
      console.log("The agent was still waiting. Re-run to continue the audit.");
      return;
    }

    const next = [];

    if (pendingQuestions.length > 0) {
      const asked = pendingQuestions.flatMap((pending) => describePending(events, pending));
      rule("PAUSED - the agent is asking a question");
      next.push(...(await answerQuestions(asked)));
    }

    if (pendingApprovals.length > 0) {
      const calls = pendingApprovals.flatMap((pending) => describePending(events, pending));
      next.push(...(await decideApprovals(calls)));
    }

    input = next;
    attachTo = null;
  }

  closePrompt();
  rule(`stopped after ${MAX_ROUNDS} rounds`);
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

// There is no --yes flag, and that is deliberate.
//
// An earlier version had one, to make demos quicker. But the whole claim this
// project makes is that a person sees the concrete write before it happens, and a
// flag that pre-approves every gated call in a scripted run defeats exactly that.
// It would also be the first thing anyone reached for in CI, which is where nobody
// is watching.
//
// --deny stays, because refusing without being asked can only ever result in less
// happening than the operator intended, never more.
