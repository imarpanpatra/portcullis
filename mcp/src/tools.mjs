// The tools this server exposes to the agent.
//
// Every one of them is read-only, and each is annotated as such. TrueForge resolves
// its @read-only / @write / @destructive approval selectors from exactly these
// annotations, so marking them honestly is what lets the harness run this whole
// server without a prompt while still gating the GitHub write that follows.

import { z } from "zod";
import { UpstreamError } from "./http.mjs";
import {
  getPackageMetadata,
  getDownloadStats,
  searchPackages,
  getBulkDownloads,
} from "./registry.mjs";
import { findAdvisories } from "./osv.mjs";
import { rankNeighbours, generateNeighbours } from "./similarity.mjs";

const packageName = z
  .string()
  .min(1)
  .describe("An npm package name, scoped or not, e.g. 'express' or '@babel/core'.");

const packageVersion = z
  .string()
  .optional()
  .describe("An exact version, e.g. '4.19.2'. Defaults to the latest published version.");

function ok(payload) {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

// A failed upstream call is information, not a crash: the agent should be able to
// say "the registry did not answer" rather than have the turn die under it.
function failed(error) {
  const detail =
    error instanceof UpstreamError
      ? { upstream_status: error.status, url: error.url }
      : { unexpected: true };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ error: error.message, ...detail }, null, 2) }],
  };
}

async function guard(work) {
  try {
    return ok(await work());
  } catch (error) {
    return failed(error);
  }
}

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };

export function registerTools(server) {
  server.registerTool(
    "get_package_metadata",
    {
      title: "Get npm package metadata",
      description:
        "Registry facts about a package: age, maintainers, publish cadence, licence, declared " +
        "lifecycle scripts (preinstall/install/postinstall), the resolved tarball URL and its " +
        "integrity hash, and the linked source repository. Start here -- the tarball URL this " +
        "returns is what the sandbox inspector needs.",
      inputSchema: { name: packageName, version: packageVersion },
      annotations: { ...READ_ONLY, title: "Get npm package metadata" },
    },
    ({ name, version }) => guard(() => getPackageMetadata(name, version)),
  );

  server.registerTool(
    "get_download_stats",
    {
      title: "Get npm download statistics",
      description:
        "Weekly downloads, the last month day by day, and the ratio between the two halves of " +
        "that month. Use it to judge whether a package is as established as its name suggests, " +
        "and to spot a sudden spike.",
      inputSchema: { name: packageName },
      annotations: { ...READ_ONLY, title: "Get npm download statistics" },
    },
    ({ name }) => guard(() => getDownloadStats(name)),
  );

  server.registerTool(
    "find_advisories",
    {
      title: "Find known vulnerabilities",
      description:
        "Known security advisories for a package from OSV, which aggregates the GitHub Advisory " +
        "Database. Omit the version to ask about the package as a whole, which is the right " +
        "question when deciding whether to adopt it at all.",
      inputSchema: { name: packageName, version: packageVersion },
      annotations: { ...READ_ONLY, title: "Find known vulnerabilities" },
    },
    ({ name, version }) => guard(() => findAdvisories(name, version)),
  );

  server.registerTool(
    "find_impersonators",
    {
      title: "Find possible typosquats",
      description:
        "Packages whose names sit within a couple of edits of this one, with their download " +
        "counts. A near-identical name with vastly more downloads means the package under " +
        "review may be impersonating it; the reverse means this package may be the target.",
      inputSchema: { name: packageName },
      annotations: { ...READ_ONLY, title: "Find possible typosquats" },
    },
    ({ name }) =>
      guard(async () => {
        // Two sources, because neither alone is sufficient. Registry search finds
        // packages that describe themselves similarly but will happily omit the
        // obvious victim -- searching for "expres" does not return "express".
        // Probing generated typo-names catches exactly that case.
        const [stats, searched, probed] = await Promise.all([
          getDownloadStats(name).catch(() => ({ weekly_downloads: 0 })),
          searchPackages(name, 25).catch(() => []),
          getBulkDownloads(generateNeighbours(name)),
        ]);

        const merged = new Map();
        for (const entry of searched) merged.set(entry.name, entry.weekly_downloads);
        // Probe results win: they are a direct download count rather than the
        // search API's monthly figure divided down.
        for (const [candidate, downloads] of probed) merged.set(candidate, downloads);

        const candidates = [...merged].map(([n, weekly_downloads]) => ({ name: n, weekly_downloads }));
        const neighbours = rankNeighbours(name, stats.weekly_downloads, candidates);

        return {
          package: name,
          weekly_downloads: stats.weekly_downloads,
          neighbours,
          impersonation_suspected: neighbours.some((n) => n.impersonation_suspected),
        };
      }),
  );

  return server;
}
