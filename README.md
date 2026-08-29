# Portcullis

**An agent that decides whether a third-party npm package is safe to let into your repository — and cannot add it without your say-so.**

Built on [TrueForge](https://trueforge.dev), TrueFoundry's open-source agent harness, for the
[Agent Harness Hackathon](https://www.wemakedevs.org/hackathons/trueforge).

---

## The problem

Adding a dependency is the least-examined write most engineers make. `npm install left-pad-utils`
runs arbitrary code from a stranger on your laptop, in your CI, and eventually in production. The
npm registry ships thousands of new versions an hour, and supply-chain attacks — typosquats,
compromised maintainer accounts, `postinstall` hooks that phone home, code published in the tarball
that never existed in the GitHub repo — arrive through exactly that door.

Nobody reads the tarball. Portcullis reads the tarball.

## What the agent does

Ask it: *"Can I add `<package>` to `<repo>`?"* It then:

1. **Gathers intelligence** through a custom MCP server — registry metadata, maintainer and publish
   history, download trend, known advisories from OSV, and near-miss package names for typosquat
   detection.
2. **Detonates the package in a sandbox** — downloads the actual tarball into an isolated Daytona
   sandbox (never your machine), unpacks it, and statically analyses what is inside: install hooks,
   obfuscated payloads, `child_process` / `net` / `dns` usage, files absent from the declared
   `files` list, and a diff between the published tarball and the project's own GitHub source.
3. **Reaches a verdict** with evidence — every claim points at a file and a line.
4. **Stops.** Admitting the dependency means a commit and a pull request against a real repository.
   That is irreversible, so the agent pauses and shows you the exact change it wants to make. It
   proceeds only when a human approves.

## Why a harness, and not a chatbot

A chat window could describe supply-chain risk. It could not do any of this:

| Requirement | How TrueForge provides it |
| --- | --- |
| Reach the npm registry, OSV, and GitHub | MCP connectors — a custom server for npm intelligence, the catalog server for GitHub |
| Execute untrusted third-party code safely | Sandbox-as-tool: the tarball is unpacked and inspected in an isolated sandbox while credentials stay in the harness |
| Refuse to act alone on an irreversible write | `require_approval_for_tools` pauses the turn on the GitHub write tools until a human allows or denies |

Remove the harness and the project stops being possible, not merely less convenient.

## Repository layout

```
mcp/                      Custom MCP server: npm registry, download stats, OSV advisories
skills/                   The audit playbook and the sandbox inspection script
agent/                    The TrueForge agent spec
sdk/                      Creates the agent and drives a session, including the approval pause
docs/                     Architecture notes
```

## Setup

Documented in full once the pieces land. See `docs/`.

## Qodo Code Review Evidence

_Filled in as pull requests merge._

## AI assistance disclosure

Per hackathon rule 12, AI coding assistants were used during this build. Details in `docs/`.
