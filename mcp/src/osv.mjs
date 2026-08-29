// Known-vulnerability lookup through OSV (osv.dev), the open vulnerability
// database maintained by Google. It aggregates the GitHub Advisory Database among
// other sources, covers npm directly, and needs no key -- which keeps this server
// connectable without handing the agent any credential at all.

import { postJson } from "./http.mjs";

const OSV_QUERY = "https://api.osv.dev/v1/query";

function highestSeverity(vulns) {
  const order = ["CRITICAL", "HIGH", "MODERATE", "LOW"];
  const found = vulns
    .map((v) => v.database_specific?.severity?.toUpperCase())
    .filter((s) => order.includes(s));
  return order.find((level) => found.includes(level)) ?? null;
}

/**
 * Advisories affecting one package version. Omitting the version asks OSV about
 * the package as a whole, which is the right question when deciding whether to
 * adopt a dependency at all rather than whether to bump one.
 */
export async function findAdvisories(name, version) {
  const query = version
    ? { version, package: { name, ecosystem: "npm" } }
    : { package: { name, ecosystem: "npm" } };

  const result = await postJson(OSV_QUERY, query);
  const vulns = result.vulns ?? [];

  return {
    package: name,
    version: version ?? "any",
    advisory_count: vulns.length,
    highest_severity: highestSeverity(vulns),
    advisories: vulns.map((vuln) => ({
      id: vuln.id,
      aliases: vuln.aliases ?? [],
      summary: vuln.summary ?? null,
      severity: vuln.database_specific?.severity ?? null,
      published: vuln.published ?? null,
      // Only the npm ranges matter here; a single OSV record can carry ranges
      // for several ecosystems at once.
      affected_ranges: (vuln.affected ?? [])
        .filter((a) => a.package?.ecosystem === "npm" && a.package?.name === name)
        .flatMap((a) => a.ranges ?? [])
        .flatMap((range) => range.events ?? []),
      references: (vuln.references ?? []).slice(0, 3).map((ref) => ref.url),
    })),
  };
}
