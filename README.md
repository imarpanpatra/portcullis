# Portcullis

**An agent that decides whether a third-party npm package is safe to let into your repository — and cannot add it without your say-so.**

Built on [TrueForge](https://trueforge.dev), TrueFoundry's open-source agent harness, for the [Agent Harness Hackathon](https://www.wemakedevs.org/hackathons/trueforge).

**▶ [Watch the demo (3 min)](https://youtu.be/t042CZAsOuM)** — the typosquat catch, five subagents auditing in parallel, the sandbox opening a real tarball, and the agent stopping to ask before it opens a pull request.

---

## The problem

Adding a dependency is the least-examined write most engineers make. `npm install some-utils` runs code from a stranger on your laptop, in your CI, and eventually in production. The registry ships thousands of new versions an hour, and supply-chain attacks arrive through exactly that door: typosquats, compromised maintainer accounts, `postinstall` hooks that phone home, and code published in the tarball that never existed in the GitHub repository anyone reviewed.

Nobody reads the tarball. Portcullis reads the tarball.

## What it does

Ask it: *"Can I add `<package>` to `<repo>`?"*

1. **Checks whether the name is the attack.** Before reading a line of code, it looks for packages one or two edits away with far more downloads. If you typed `expres` you want to be told about `express`, not handed a security report.
2. **Gathers registry signals.** Age, publish cadence, maintainer count, download trend, and known advisories from OSV.
3. **Detonates the package in a sandbox.** Downloads the real tarball into an isolated Daytona sandbox — never your machine — unpacks it, and reads what actually ships: install hooks, obfuscated payloads, `child_process` and socket use, shipped binaries, and a diff between the published tarball and the project's own GitHub source at that tag.
4. **Reaches a verdict with evidence.** Every claim points at a file and a line.
5. **Stops.** Admitting the package means a commit and a pull request against a real repository. That is irreversible, so the agent shows you the exact change it wants to make and waits. It proceeds only when a human approves.

## Why this needs a harness, not a chat window

A chat window could describe supply-chain risk in the abstract. It could not do any of this:

| Requirement | What TrueForge provides |
| --- | --- |
| Reach the npm registry, OSV, and GitHub | MCP connectors — a custom server for npm intelligence, the catalog server for GitHub |
| Execute untrusted third-party code safely | Sandbox-as-tool. The tarball is unpacked and read in an isolated sandbox while model and connector credentials stay in the harness |
| Refuse to act alone on an irreversible write | `require_approval_for_tools` ends the turn before a gated call and will not resume without a `user.tool_approval` event |
| Ask rather than guess | `ask_user_question` — used the moment a package name looks like a typo |
| Audit several packages at once | Subagents — one per package, run in parallel, results merged into one ranked report |
| Survive the client going away | Sessions hold context server-side, and a dropped stream reattaches to the same turn rather than restarting it |
| Show a person what is happening | Generative UI — the verdict, the signals with the tool each came from, and the findings kept *and dropped*, rendered as components in the chat UI |

Take the harness away and the project stops being possible, not merely less convenient.

## Architecture

```
        you ──────────────────────────────► sdk/audit.mjs
                                                  │            session id ──► resume later
                                      TrueForge harness (agent loop)
                                                  │
                              one subagent per package, in parallel
                             ┌────────────────────┼────────────────────┐
                             ▼                    ▼                    ▼
                        audit-express         audit-chalk          audit-ms
                             │                    │                    │
                     ┌───────┴──────┐             │                    │
                     ▼              ▼             ▼                    ▼
            portcullis MCP    Daytona sandbox                  ... same tools ...
          (mcp/, read-only)  (skills/supply-chain-audit)
                     │              │
       registry · downloads · OSV   unpack tarball, read code,
                                    diff against GitHub source
                             merged, ranked, one verdict per package
                                                  │
                                                  ▼
                                            github MCP  (catalog, GATED)
                                       branch · commit · pull request
                                                  │
                                      ⏸ pauses for human approval
```

| Directory | What it is |
| --- | --- |
| `mcp/` | Custom MCP server. Four read-only tools over public keyless APIs |
| `skills/supply-chain-audit/` | The audit playbook (`SKILL.md`) and the sandbox inspector, cloned into the sandbox on demand |
| `agent/` | The agent spec — model, instructions, connectors, and the approval gate |
| `sdk/` | Registers everything on a TrueForge server, and runs an audit from the terminal |

## Setup

**Requirements:** Node 22.14+, Python 3 (in the sandbox image), a model provider API key, and a [Daytona](https://www.daytona.io) API key.

```bash
git clone https://github.com/imarpanpatra/portcullis && cd portcullis

# 1. Start TrueForge
npx @truefoundry/trueforge@latest          # http://localhost:8790

# 2. Start the npm intelligence MCP server (separate terminal)
cd mcp && npm install && npm start          # http://localhost:8941/mcp
```

In the TrueForge UI:

- **Settings → Models** — add your provider and paste an API key.
- **Settings → Sandbox providers** — choose Daytona and paste an API key. The key needs **Snapshots create** permission as well as Sandboxes; without it, configuring the provider fails even though the key is otherwise valid.
- **Settings → Connectors** — connect **GitHub**. It uses OAuth, so a person has to authorise it; this is the one piece the setup script cannot do for you.

Then register the connector, the skill, and the agent. **Choose the model first** — the agent is created with whatever `PORTCULLIS_MODEL` says at that moment, and without it the first configured model wins, which may be the mini-class model that [skips tarball inspection](#what-running-it-for-real-changed):

```bash
cd sdk && npm install
export PORTCULLIS_MODEL=openai/gpt-5-5      # must be set BEFORE the next line
npm run create-agent
```

`create-agent` is create-or-replace, so if you get this wrong just export the right model and run it again — it updates the existing agent rather than making a second one. The line it prints as `Model :` is the one the agent will actually use; check it.

Other environment variables: `TRUEFORGE_BASE_URL`, `PORTCULLIS_MCP_URL`, `PORTCULLIS_SKILL_REPO`, `PORTCULLIS_SKILL_REF`.

## Two ways to drive it

**The chat UI** at `http://localhost:8790` — shipped with TrueForge. Pick the
`portcullis` agent and ask it about a package. It streams the agent's steps, shows a
thread per subagent, renders the audit report as components rather than markdown, and
puts **Allow / Deny** in front of the write with the tool and its arguments on screen.
This is the one to use if you only try it once.

**The terminal**, below, for driving the same agent from code — and for showing that
the approval gate lives in the harness rather than in the client's manners.

## Running an audit

```bash
node audit.mjs express                                  # audit one package
node audit.mjs express chalk ms left-pad                # audit several, one subagent each
node audit.mjs left-pad --repo you/your-demo-repo       # audit, then offer to open a PR
node audit.mjs lodash  --repo you/your-demo-repo --deny # refuse the write and watch it stop
node audit.mjs axios   --session <id>                   # continue an earlier session
```

Given more than one package the agent **fans out**, giving each its own subagent and
merging the results into a single ranked report with a verdict per package. The audits
are independent, so nothing is gained by making the reviewer wait on the slowest
tarball, and each packument stays out of the main context.

Every run prints its session id. Sessions keep their context on the server, so
`--session` resumes one that already knows what was audited and decided earlier. If
the stream drops mid-turn the runner **reattaches to the same turn** rather than
starting over — the work is running on the server, and re-running tool calls that
already happened is the wrong kind of retry for an agent that writes to repositories.

There is deliberately **no `--yes`**. A flag that pre-approves every gated write defeats the only claim this project makes, and it would be the first thing anyone reached for in CI — which is exactly where nobody is watching.

## What it actually finds

Verified against live packages:

| Package | Verdict | Is that right? |
| --- | --- | --- |
| `express`, `chalk`, `ms` | silent — no findings | Yes. A tool that cries wolf on express teaches you to ignore it |
| `esbuild` | high — `postinstall`, `child_process`, egress to `snapcraft.io`, and an extensionless `bin/esbuild` that spawns a subprocess | Yes, every finding is true. It really does fetch a platform binary at install time. This is an *admit with conditions*, not a refusal |
| `expres` | no code findings, but flagged at the **name** level: 5,213 weekly downloads sitting one edit from express's 132 million | Yes. It is an abandoned 13-year-old package, not malware. The typo is the finding |

That last row is the one worth defending. The tool's job is to be right, not alarming.

### A real end-to-end run

Audited `left-pad`, raised two `network_egress` candidates, verified both against the shipped files and dropped them as WTFPL licence-comment URLs, set its own condition (pin exactly `1.3.0`, not a caret range), paused three times - `create_branch`, `create_or_update_file`, `create_pull_request` - and on approval opened [portcullis-demo#1](https://github.com/imarpanpatra/portcullis-demo/pull/1) honouring that condition in the diff. Run with `--deny`, it acknowledges the refusal and stops rather than looking for another route.

## Testing

Three layers, cheapest first. The first two need nothing but a clone.

**1. The inspector, offline (57 tests, no network):**

```bash
python3 -m unittest discover -s skills/supply-chain-audit/tests -v
```

Every fixture is built in memory, so nothing malicious is ever downloaded. It includes
cases that attack the inspector itself — a tar member named `../../escaped.txt`, an
absolute path, a symlink to `/etc/passwd`, and a decompression bomb — plus the
calibration cases that keep it quiet on ordinary packages.

**2. The MCP server against the live registry (22 assertions):**

```bash
cd mcp && npm install && node smoke.mjs
```

Covers scoped names, unknown and blank versions, a package with known critical
advisories, and the `expres`/`express` typosquat case.

**3. The inspector against a real package, end to end:**

```bash
python3 skills/supply-chain-audit/scripts/inspect_package.py   --name esbuild --version 0.28.2   --tarball https://registry.npmjs.org/esbuild/-/esbuild-0.28.2.tgz   --repo-url https://github.com/evanw/esbuild
```

`express`, `chalk` and `ms` should come back with **zero findings**. `esbuild` should
report `install_script`, `process_execution` and `network_egress` — all true, and the
right answer is *admit with conditions*, not refuse. If a benign package starts
producing findings, that is the regression to care about: a tool that cries wolf on
express teaches you to ignore it.

**4. The whole agent** — needs a running TrueForge, per [Setup](#setup):

```bash
cd sdk
node audit.mjs express                       # sandbox + tools, no writes
node audit.mjs express chalk ms              # subagents fan out
node audit.mjs left-pad --repo you/demo --deny   # the gate fires and is refused
```

## Qodo Code Review Evidence

Every substantive change went through a pull request reviewed by [Qodo](https://qodo.ai) before merge. Across five pull requests Qodo raised **23 findings**. All 23 were assessed and answered individually in-thread; **22 were valid and fixed**, and one was disputed with the reason recorded.

**Representative merged PR: [#2 - Add the supply-chain audit skill and sandbox inspector](https://github.com/imarpanpatra/portcullis/pull/2)** (16 findings over four review rounds)

The findings that mattered most, all in the inspector:

- `compare_with_source` computed repository content hashes and then never compared them, so a maliciously modified file published at an existing path passed clean.
- Tarball-only files under `dist/` were reduced to a counter, meaning an injected `dist/index.js` - frequently the actual entry point - produced no finding at all.
- Shell scripts were classified as unreadable binaries, so a `postinstall` invoking `install.sh` containing `curl ... | bash` skipped the very check written to catch it.
- Classification was a lowercase extension allowlist, so `INSTALL.SH` and an extensionless `bin/setup` were invisible. Files without an extension are now classified by content. This immediately surfaced esbuild's `bin/esbuild`, which does spawn a subprocess.

**The review found defects that my own fixes introduced.** The extraction caps added in round one let a truncated repository tree manufacture false critical findings. Capping every finding in response then went too far the other way and understated a *proven* content mismatch. Teaching the scanner to read `.sh` files without extending the provenance check left shell scripts half-examined. Three of the four rounds on #2 were corrections to earlier corrections, which is the honest argument for why the review mattered: a single clean pass would have found none of them.

**The one I disputed:** on [#3](https://github.com/imarpanpatra/portcullis/pull/3) and [#4](https://github.com/imarpanpatra/portcullis/pull/4) Qodo reported the audit skill and the runner as missing. Both were artefacts of branch ordering rather than defects, and I said so in-thread rather than manufacturing a change. The *substantive* half of the #3 finding was real and fixed: the runner referenced the skill without ever registering it, so a fresh server would have produced an agent that could not load its own procedure.

**[#5](https://github.com/imarpanpatra/portcullis/pull/5)** carries everything that only first contact with a live sandbox could reveal, plus two findings that arrived on #2 and #3 after they had merged.

Trail: 23 findings, 23 replies, fix commits against each round, and follow-up reviews run against the final code on every pull request.

## What running it for real changed

Nothing below was reachable from a developer machine, and all of it is in the history:

- **The sandbox had no `bash`.** Every `exec` failed, the agent tried three shell variations, gave up, and answered from registry metadata alone - a confident verdict that had never opened the package. The fix was not to find a shell but to stop needing one: the inspector exposes `audit()` and the skill imports it under Code Mode.
- **The documented skills path was wrong.** Docs say `/opt/tfy/skills`; the server logs `/opt/tf/skills`.
- **The model mattered more than the prompt.** On a mini-class model the agent skipped the skill entirely - it has registry tools that answer in a second and a sandbox step that does not, so it took the fast path and sounded equally certain having looked at strictly less. `gpt-5-5` loads the skill and quotes the inspector's own report back. Use it.
- **`get_package_metadata` rejected its own caller.** A model that does not know the version sends `""`, and `"" ?? latest` is `""`.

### Running on Windows

TrueForge v0.1.4 fails to start on Windows: `kysely`'s `FileMigrationProvider` passes a raw `C:\...` path to `import()`, which Node rejects because `c:` reads as a protocol scheme. Patch `node_modules/kysely/dist/migration/file-migration-provider.js` to wrap the path in `pathToFileURL(filePath).href`. Note also that the local sandbox fallback is macOS and Linux only, so Daytona is required rather than optional.

## AI assistance disclosure

Per hackathon rule 12: an AI coding assistant (Claude, via Claude Code) was used throughout this build — for implementation, for working through Qodo's findings, and for drafting documentation. Design decisions, the choice of what to build, the severity calibration, the judgement calls on each review finding, and the decision to remove the `--yes` flag were made by me, and I can explain any part of the codebase.

## Licence

MIT. See [LICENSE](LICENSE).
