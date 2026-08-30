# Portcullis

**An agent that decides whether a third-party npm package is safe to let into your repository — and cannot add it without your say-so.**

Built on [TrueForge](https://trueforge.dev), TrueFoundry's open-source agent harness, for the [Agent Harness Hackathon](https://www.wemakedevs.org/hackathons/trueforge).

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

Take the harness away and the project stops being possible, not merely less convenient.

## Architecture

```
        you ──────────────────────────────► sdk/audit.mjs
                                                  │
                                      TrueForge harness (agent loop)
                                       │           │            │
                     ┌─────────────────┘           │            └──────────────┐
                     ▼                             ▼                           ▼
            portcullis MCP                  Daytona sandbox              github MCP
          (mcp/, read-only)          (skills/supply-chain-audit)        (catalog, GATED)
                     │                             │                           │
       registry · downloads · OSV      unpack tarball, read code,        branch · commit
                                        diff against GitHub source        · pull request
                                                                                │
                                                                    ⏸ pauses for approval
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

Then register the connector, the skill, and the agent:

```bash
cd sdk && npm install && npm run create-agent
```

Optional environment variables: `PORTCULLIS_MODEL` (a fully qualified `provider/model`; otherwise the first configured model is used), `TRUEFORGE_BASE_URL`, `PORTCULLIS_MCP_URL`, `PORTCULLIS_SKILL_REPO`, `PORTCULLIS_SKILL_REF`.

## Running an audit

```bash
node audit.mjs express                                  # audit only
node audit.mjs left-pad --repo you/your-demo-repo       # audit, then offer to open a PR
node audit.mjs lodash  --repo you/your-demo-repo --deny # refuse the write and watch it stop
```

There is deliberately **no `--yes`**. A flag that pre-approves every gated write defeats the only claim this project makes, and it would be the first thing anyone reached for in CI — which is exactly where nobody is watching.

## What it actually finds

Verified against live packages:

| Package | Verdict | Is that right? |
| --- | --- | --- |
| `express`, `chalk`, `ms` | silent — no findings | Yes. A tool that cries wolf on express teaches you to ignore it |
| `esbuild` | high — `postinstall`, `child_process`, egress to `snapcraft.io`, and an extensionless `bin/esbuild` that spawns a subprocess | Yes, every finding is true. It really does fetch a platform binary at install time. This is an *admit with conditions*, not a refusal |
| `expres` | no code findings, but flagged at the **name** level: 5,213 weekly downloads sitting one edit from express's 132 million | Yes. It is an abandoned 13-year-old package, not malware. The typo is the finding |

That last row is the one worth defending. The tool's job is to be right, not alarming.

## Tests

```bash
node mcp/smoke.mjs                                              # 18 assertions, live APIs
python3 -m unittest discover -s skills/supply-chain-audit/tests # 50 tests, fully offline
```

The offline suite builds every fixture in memory — nothing malicious is downloaded — and includes cases that attack the inspector itself with path traversal, absolute paths, symlinks to `/etc/passwd`, and a decompression bomb.

## Qodo Code Review Evidence

Every substantive change went through a pull request reviewed by [Qodo](https://qodo.ai) before merge.

**Representative merged PR: [#2 — Add the supply-chain audit skill and sandbox inspector](https://github.com/imarpanpatra/portcullis/pull/2)**

Across three review rounds on that PR, Qodo raised **14 findings (7 High, 7 Medium)**. All were assessed as valid, **none were dismissed**, and each was fixed and answered individually in its thread. The most consequential: `compare_with_source` computed repository content hashes and then never compared them, so a maliciously modified file published at an existing path passed clean; tarball-only files under `dist/` were reduced to a counter, meaning an injected `dist/index.js` — often the actual entry point — produced no finding at all; and shell scripts were classified as unreadable binaries, so a `postinstall` invoking `install.sh` containing `curl … | bash` skipped the very check written to catch it.

Two rounds are worth reading in full, because the second and third found defects that *my own fixes introduced*: the extraction caps added in round one let a truncated repository tree manufacture false critical findings, and teaching the scanner to read `.sh` files without extending the provenance check left shell scripts only half-examined.

On **[#3 — Add the agent spec and the SDK runner](https://github.com/imarpanpatra/portcullis/pull/3)** Qodo raised 3 findings. One was **partly disputed and the disagreement recorded in-thread**: it reported the audit skill as missing, which was an artefact of branch ordering rather than a defect, and I said so. The substantive half of that finding was real and fixed — the runner referenced the skill without ever registering it, so a fresh server would have produced an agent that could not load its own procedure. Another found that the runner collected only approval pauses and not question pauses, which would have terminated the most common path through the agent — the typosquat question — with no verdict.

**Trail:** 17 findings, 17 replies, fix commits against each round, and a follow-up review run against the final code on both PRs.

## AI assistance disclosure

Per hackathon rule 12: an AI coding assistant (Claude, via Claude Code) was used throughout this build — for implementation, for working through Qodo's findings, and for drafting documentation. Design decisions, the choice of what to build, the severity calibration, the judgement calls on each review finding, and the decision to remove the `--yes` flag were made by me, and I can explain any part of the codebase.

## Licence

MIT. See [LICENSE](LICENSE).
