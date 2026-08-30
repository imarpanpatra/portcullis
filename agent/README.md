# The agent spec

`portcullis.agent.json` is the whole agent: a model, its instructions, the connectors
and skill it may use, and how the harness should behave while it runs.

Create it with:

```bash
cd sdk && npm install && npm run create-agent
```

That one command registers three things, because an agent spec only *references*
its connectors and skills by name. A reference to a skill the server has never been
told about produces an agent that cannot load its own procedure, so the reference
and the registration have to travel together:

| Registered | How |
| --- | --- |
| `portcullis` connector | `PUT /api/v1/settings/mcp-servers`, pointed at the local MCP server |
| `supply-chain-audit` skill | `PUT /api/v1/settings/skills`, git-backed and cloned into the sandbox on demand |
| `portcullis` agent | `client.agents.create` / `update` |

`PUT` is create-or-replace, so the script is safe to re-run.

The **GitHub connector is the one piece this cannot set up**: it is an OAuth catalog
entry, so a person has to authorise it under Settings → Connectors. The script
checks for it and warns loudly rather than quietly creating an agent whose write
path does not exist.

## Why this is created through the SDK and not the chat UI

The chat UI covers model, instructions, connectors, skills, and the sandbox toggle.
It does **not** cover `require_approval_for_tools`, which is the single most
important line in this file. Building the agent by hand in the UI would leave the
approval policy at its default, and the default is not what this agent needs.

## The approval gate

```json
"require_approval_for_tools": [
  "@write", "@destructive",
  "create_pull_request", "create_or_update_file", "push_files", ...
]
```

Two kinds of entry, deliberately. The `@write` and `@destructive` selectors are
resolved from the annotations the MCP server publishes about its own tools, so they
cover every write the GitHub connector exposes — including any added after this file
was written. The literal names cover the case where a tool is mis-annotated or not
annotated at all.

Belt and braces, because the failure mode is silent. A gate that names only literal
tools and gets one name wrong does not error; it simply never fires, and the agent
opens a pull request nobody approved. Listing both means a tool has to escape *both*
its annotation and the name list to slip through.

The `portcullis` connector needs no gate at all: every tool on it is annotated
`readOnlyHint`, so the harness runs it autonomously. Reading the registry is not a
decision anyone needs to confirm.

## The model

`model.name` ships as `REPLACE_WITH_YOUR_MODEL`. `create-agent.mjs` substitutes it,
in this order:

1. `PORTCULLIS_MODEL`, if set — a fully qualified `provider/model`, e.g. `openai/gpt-5-5`.
   **Export it before running the script**: the agent is created with whatever the value is
   at that moment.
2. Otherwise it asks your TrueForge server which models you have configured and
   takes the first, printing which one it chose. Convenient, but not a safe default to
   rely on — a mini-class model will skip the tarball inspection entirely and still sound
   certain. Check the `Model :` line the script prints.

So a judge running this does not have to know which provider you happened to use.
Agent definitions never contain API keys — the model is referenced by name and the
credentials stay in the harness.

## Two kinds of pause

`config.ask_user_questions` is enabled alongside the approval gate, and the runner
handles both. They are different stops:

| Event | Means | Resumed with |
| --- | --- | --- |
| `tool.approval_required` | The agent wants to make an irreversible write | `user.tool_approval` |
| `tool.response_required` | The agent is asking something it should not guess | `user.tool_response` |

Both end the turn. A client that collects only approvals looks fine until the first
audit that needs a question answered, at which point the turn ends, nothing is
pending as far as the client knows, and the session exits with no verdict. That
matters here more than it might elsewhere, because the skill instructs the agent to
ask *"did you mean express?"* the moment a name looks like a typosquat — the most
common path through this agent is the one that asks.

## There is no --yes flag

`audit.mjs` deliberately has no unattended-approval flag. The claim this project
makes is that a person sees the concrete write before it happens; a flag that
pre-approves every gated call defeats that, and it would be the first thing anyone
reached for in CI, which is precisely where nobody is watching.

`--deny` stays, because refusing without being asked can only ever result in less
happening than the operator intended, never more.

## Instructions versus skill

The instructions say what this agent *is* and what it must never do. The procedure
lives in `skills/supply-chain-audit/SKILL.md`, which the harness loads only when the
agent decides it is relevant. That split is deliberate: TrueForge appends its own
guidance for every capability that is switched on, so a bloated system prompt
competes with the harness rather than complementing it.
