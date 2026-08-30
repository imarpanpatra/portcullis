# Demo script (about three minutes)

The recording has to show three things, because a judge is checking for them
specifically: the harness reaching a real tool, code running in a sandbox, and the
agent stopping for a person before something irreversible.

Have running beforehand: TrueForge on 8790, the npm MCP server on 8941, a terminal,
and a throwaway public repo with a `package.json`.

Set the model before the agent is created, and check the `Model :` line:

```bash
export PORTCULLIS_MODEL=openai/gpt-5-5
cd sdk && npm run create-agent
```

A mini-class model skips the tarball inspection and answers from registry data alone,
which would quietly remove the sandbox from the demo you are about to record.

## 0:00 — The problem (20s)

> "Adding a dependency is the least-examined write most engineers make. `npm
> install` runs a stranger's code on your laptop, in CI, and in production. Nobody
> reads the tarball."

Show `agent/portcullis.agent.json` on screen. Point at `require_approval_for_tools`.

> "Portcullis reads the tarball. And it can't add anything without asking."

## 0:20 — The typo case (35s)

```bash
node audit.mjs expres
```

The agent calls `find_impersonators`, sees a package one edit from express with
132 million weekly downloads against its 5,000, and **asks a question rather than
guessing**. That pause is the `ask_user_question` capability.

> "It didn't write me a security report. It asked whether I'd made a typo. That
> pause is the harness — the turn ends and won't resume until I answer."

Answer it. Let it finish.

## 0:55 — The real audit and the sandbox (60s)

```bash
node audit.mjs esbuild --repo <you>/portcullis-demo
```

Let the agent work. On screen, point out as they stream past:

- the MCP tool calls — registry, downloads, OSV (**a real tool reached**)
- the sandbox provisioning, and the skill being cloned into it
- the inspector unpacking the tarball and reading it (**code running in a sandbox**)

> "That tarball is being unpacked somewhere isolated, not here. This is the step
> that would otherwise mean running a stranger's archive on my own machine."

Show the findings: the `postinstall`, the `child_process` use, the egress to
`snapcraft.io`, the extensionless `bin/esbuild`.

> "Every one of these is true. esbuild really does download a platform binary at
> install time. The verdict is 'admit with conditions', not 'refuse' — a tool that
> panics about esbuild is a tool nobody will use."

## 1:40 — Fan-out (20s)

```bash
node audit.mjs ms chalk left-pad
```

Three subagents start at once, one per package. Point at the `[subagent N]` lines.

> "Nobody adds one dependency. Each of these gets its own subagent, they run in
> parallel, and the results come back merged with a verdict per package — admit,
> admit, admit-with-conditions. That fan-out is the harness, not something I wrote."

Also point at the session id printed at the top:

> "That session lives on the server. If I close this terminal the work carries on,
> and I can rejoin it with --session. If the stream drops mid-turn it reattaches to
> the same turn rather than starting over — which matters, because restarting would
> re-run writes that already happened."

## 2:00 — The gate (50s)

The agent proposes the pull request and the turn **stops**. The terminal prints the
tool name and the exact arguments.

> "This is the moment the whole project exists for. It wants to write to a real
> repository. The turn has ended. The harness will not resume until it receives an
> approval event — so if I close this terminal, nothing happens."

Approve it. Show the pull request appear on GitHub.

Then run the same thing again with `--deny` and show the agent acknowledge the
refusal and stop rather than looking for another route.

> "There is no `--yes` flag, deliberately. A flag that pre-approves every write
> defeats the only claim this project makes."

## 2:50 — Close (10s)

> "Four connectors' worth of real data, a sandbox doing the dangerous part, and a
> gate that a client cannot talk its way past. Every change here went through a
> Qodo-reviewed pull request — seventeen findings, all answered."

Show the PR list with the Qodo threads.

## Recording notes

- Keep keys off screen. Check the terminal scrollback before recording.
- Use a throwaway repo for the write. Never a repo you care about.
- If the sandbox is slow to provision, cut that gap in the edit — do not cut the
  pause itself.
