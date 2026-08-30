// Smoke test for the four tools, run against the live public APIs.
//
// It calls the modules directly rather than going through MCP, because what is
// worth checking here is that the upstream shapes have not moved -- the transport
// wiring is exercised by connecting the server to TrueForge.
//
//   node smoke.mjs

import {
  getPackageMetadata,
  getDownloadStats,
  searchPackages,
  getBulkDownloads,
} from "./src/registry.mjs";
import { findAdvisories } from "./src/osv.mjs";
import { rankNeighbours, generateNeighbours } from "./src/similarity.mjs";

const checks = [];

function check(label, condition, detail = "") {
  checks.push({ label, pass: Boolean(condition), detail });
  console.log(`${condition ? "PASS" : "FAIL"}  ${label}${detail ? `  ${detail}` : ""}`);
}

console.log("\n--- get_package_metadata(express) ---");
const express = await getPackageMetadata("express");
check("resolves a version", Boolean(express.version), express.version);
check("finds the repository", Boolean(express.repository_url), express.repository_url ?? "");
check("reports package age", express.package_age_days > 3000, `${express.package_age_days} days`);
check("returns a tarball url", Boolean(express.tarball.url), express.tarball.url ?? "");
check("lists maintainers", express.maintainer_count > 0, `${express.maintainer_count}`);

console.log("\n--- get_package_metadata(@babel/core, scoped) ---");
const babel = await getPackageMetadata("@babel/core");
check("handles a scoped name", babel.name === "@babel/core", babel.version ?? "");

console.log("\n--- get_package_metadata(express, bad version) ---");
const missing = await getPackageMetadata("express", "999.999.999");
check("reports an unknown version", Boolean(missing.error), missing.error ?? "");

console.log("\n--- get_package_metadata(express, blank version) ---");
// A model that does not know the version sends "" rather than omitting the field.
for (const blank of ["", "   ", null, undefined]) {
  const resolved = await getPackageMetadata("express", blank);
  check(
    `treats ${JSON.stringify(blank)} as latest`,
    !resolved.error && Boolean(resolved.version),
    resolved.version ?? resolved.error ?? "",
  );
}

console.log("\n--- get_download_stats(express) ---");
const stats = await getDownloadStats("express");
check("returns weekly downloads", stats.weekly_downloads > 1_000_000, `${stats.weekly_downloads}`);
check("returns a month of dailies", stats.daily.length > 25, `${stats.daily.length} days`);
check("computes a trend ratio", stats.trend_ratio !== null, `${stats.trend_ratio}`);

console.log("\n--- find_advisories(lodash@4.17.11) ---");
const advisories = await findAdvisories("lodash", "4.17.11");
check("finds known advisories", advisories.advisory_count > 0, `${advisories.advisory_count} found`);
check("ranks a severity", Boolean(advisories.highest_severity), advisories.highest_severity ?? "");

console.log("\n--- find_advisories(express, clean version) ---");
const clean = await findAdvisories("express", "4.21.2");
check("handles a clean result", Array.isArray(clean.advisories), `${clean.advisory_count} found`);

console.log("\n--- find_impersonators(expres) ---");
const searched = await searchPackages("expres", 25);
check("searches the neighbourhood", searched.length > 0, `${searched.length} search hits`);
check(
  "search alone misses the victim",
  !searched.some((c) => c.name === "express"),
  "which is why the generated probe exists",
);

const generated = generateNeighbours("expres");
const probed = await getBulkDownloads(generated);
check("generates typo candidates", generated.length > 10, `${generated.length} generated`);
check("probe resolves real packages", probed.size > 0, `${probed.size} exist`);

const merged = new Map(searched.map((c) => [c.name, c.weekly_downloads]));
for (const [name, downloads] of probed) merged.set(name, downloads);
const neighbours = rankNeighbours(
  "expres",
  probed.get("expres") ?? 0,
  [...merged].map(([name, weekly_downloads]) => ({ name, weekly_downloads })),
);
check(
  "flags express as the impersonated package",
  neighbours.some((n) => n.name === "express" && n.impersonation_suspected),
  neighbours
    .slice(0, 3)
    .map((n) => `${n.name}(d=${n.edit_distance})`)
    .join(" "),
);

const failures = checks.filter((c) => !c.pass);
console.log(`\n${checks.length - failures.length}/${checks.length} passed`);
if (failures.length > 0) {
  console.error("failed:", failures.map((f) => f.label).join(", "));
  process.exit(1);
}
