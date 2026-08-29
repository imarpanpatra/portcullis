# Portcullis MCP server

The connector that gives the agent its npm intelligence. Four read-only tools over
public, keyless APIs — the npm registry, the npm downloads API, and OSV.

## Run it

```bash
npm install
npm start          # http://localhost:8941/mcp
```

Register it in TrueForge under **Settings → Connectors → Add MCP Server**, name it
`portcullis`, URL `http://localhost:8941/mcp`, auth **none**.

## Tools

| Tool | Answers |
| --- | --- |
| `get_package_metadata` | How old is it, who publishes it, does it declare install hooks, where is the tarball and the source repo |
| `get_download_stats` | Is it as established as its name suggests, and is the trend sudden |
| `find_advisories` | What does OSV already know about it |
| `find_impersonators` | Is this name sitting next to a far more popular one |

All four are annotated `readOnlyHint: true`. TrueForge resolves its `@read-only` /
`@write` / `@destructive` approval selectors from those annotations, so this whole
server runs without prompting while the GitHub write that follows stays gated.

## A note on typosquat detection

The obvious approach — search the registry for the package name and look at the
neighbours — does not work. Ask npm to search for `expres` and `express` is nowhere
in the twenty-five results. The victim is missing from the very query designed to
find it.

So `find_impersonators` does not rely on search. It generates the names an attacker
would plausibly have registered (deletions, adjacent transpositions, doubled
letters, separator variants, homoglyph swaps such as `l`→`1` and `rn`→`m`, and the
usual `node-x` / `x-js` dressing) and probes for them directly. The downloads API
takes up to 128 names per request and returns `null` for ones that do not exist,
which turns a few hundred candidate probes into two or three HTTP calls.

Search results are still merged in, since they catch packages that impersonate by
description rather than by name.

## Smoke test

```bash
node smoke.mjs
```

Eighteen assertions against the live APIs, covering scoped names, unknown versions,
a package with known critical advisories, and the `expres`/`express` case above.
