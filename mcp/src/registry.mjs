// npm registry client. The registry's full packument for a popular package runs to
// megabytes -- lodash carries several hundred version objects -- so nothing here
// returns the raw document. Each function trims to the handful of fields that
// actually bear on whether a package is trustworthy, and the agent reasons over
// that instead of paying for the rest in context.

import { getJson } from "./http.mjs";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads";

// A scoped name has to be encoded as @scope%2fname for the registry path.
function encodeName(name) {
  return name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name);
}

function daysBetween(from, to) {
  return Math.round((to.getTime() - from.getTime()) / 86_400_000);
}

function repositoryUrl(repository) {
  if (!repository) return null;
  const url = typeof repository === "string" ? repository : repository.url;
  if (!url) return null;
  // Normalise the git+ssh and git: forms into a plain https URL, so the sandbox
  // inspector can clone or fetch the source without special-casing each variant.
  return url
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^ssh:\/\/git@/, "https://")
    .replace(/\.git$/, "");
}

/**
 * Metadata for one package, optionally pinned to a version. Returns publish
 * cadence, maintainer count, the resolved tarball, and whether the version
 * declares lifecycle scripts -- the fields a supply-chain review turns on.
 */
export async function getPackageMetadata(name, version) {
  const packument = await getJson(`${REGISTRY}/${encodeName(name)}`);

  const distTags = packument["dist-tags"] ?? {};
  // A model that does not know the version tends to send an empty string rather
  // than omitting the field, and `"" ?? latest` is `""`. Treat any blank as absent,
  // or the caller gets told their own placeholder does not exist.
  const requested = typeof version === "string" ? version.trim() : version;
  const resolved = requested || distTags.latest;
  const versionDoc = packument.versions?.[resolved];
  if (!versionDoc) {
    const known = Object.keys(packument.versions ?? {});
    return {
      error: `Version "${resolved}" not found for ${name}.`,
      available_versions: known.slice(-20),
      total_versions: known.length,
    };
  }

  const times = packument.time ?? {};
  const now = new Date();
  const created = times.created ? new Date(times.created) : null;
  const publishedAt = times[resolved] ? new Date(times[resolved]) : null;

  // A burst of releases in the last week is how a hijacked maintainer account
  // usually looks from the outside.
  const recentReleases = Object.entries(times)
    .filter(([key]) => key !== "created" && key !== "modified")
    .filter(([, iso]) => daysBetween(new Date(iso), now) <= 7).length;

  const scripts = versionDoc.scripts ?? {};
  const lifecycleHooks = ["preinstall", "install", "postinstall", "prepare", "prepublish"].filter(
    (hook) => typeof scripts[hook] === "string",
  );

  return {
    name: packument.name,
    version: resolved,
    description: packument.description ?? null,
    license: versionDoc.license ?? packument.license ?? null,
    homepage: packument.homepage ?? null,
    repository_url: repositoryUrl(versionDoc.repository ?? packument.repository),
    deprecated: versionDoc.deprecated ?? null,
    maintainers: (packument.maintainers ?? []).map((m) => m.name),
    maintainer_count: (packument.maintainers ?? []).length,
    published_by: versionDoc._npmUser?.name ?? null,
    first_published: times.created ?? null,
    package_age_days: created ? daysBetween(created, now) : null,
    version_published: times[resolved] ?? null,
    version_age_days: publishedAt ? daysBetween(publishedAt, now) : null,
    total_versions: Object.keys(packument.versions ?? {}).length,
    releases_last_7_days: recentReleases,
    dist_tags: distTags,
    declares_lifecycle_scripts: lifecycleHooks,
    scripts,
    dependencies: versionDoc.dependencies ?? {},
    tarball: {
      url: versionDoc.dist?.tarball ?? null,
      integrity: versionDoc.dist?.integrity ?? versionDoc.dist?.shasum ?? null,
      unpacked_size_bytes: versionDoc.dist?.unpackedSize ?? null,
      file_count: versionDoc.dist?.fileCount ?? null,
    },
  };
}

/**
 * Weekly downloads plus a coarse read on the trend. A package with a handful of
 * downloads that suddenly spikes is worth a second look; so is one whose numbers
 * do not support the reputation its name implies.
 */
export async function getDownloadStats(name) {
  const encoded = encodeName(name);
  const [point, range] = await Promise.all([
    getJson(`${DOWNLOADS_API}/point/last-week/${encoded}`),
    getJson(`${DOWNLOADS_API}/range/last-month/${encoded}`),
  ]);

  const daily = range.downloads ?? [];
  const half = Math.floor(daily.length / 2);
  const earlier = daily.slice(0, half).reduce((sum, day) => sum + day.downloads, 0);
  const later = daily.slice(half).reduce((sum, day) => sum + day.downloads, 0);

  return {
    package: name,
    weekly_downloads: point.downloads ?? 0,
    last_month_total: daily.reduce((sum, day) => sum + day.downloads, 0),
    first_half_of_month: earlier,
    second_half_of_month: later,
    // Guard the divide: a package at zero downloads has no meaningful ratio.
    trend_ratio: earlier > 0 ? Number((later / earlier).toFixed(2)) : null,
    daily,
  };
}

/**
 * Registry search, used to find the neighbourhood a package name sits in. The
 * caller pairs these with download counts to spot impersonation.
 */
export async function searchPackages(text, size = 20) {
  const url = `${REGISTRY}/-/v1/search?text=${encodeURIComponent(text)}&size=${size}`;
  const results = await getJson(url);
  return (results.objects ?? []).map((entry) => ({
    name: entry.package.name,
    version: entry.package.version,
    description: entry.package.description ?? null,
    // The search API reports downloads over the last month; normalise to weekly
    // so the number is comparable with getDownloadStats.
    weekly_downloads: Math.round((entry.downloads?.monthly ?? 0) / 4.33),
  }));
}

// The downloads API accepts a comma-separated list and answers for all of them in
// one request, returning null for names that do not exist. That makes it a cheap
// existence-and-popularity probe: a few hundred candidate typosquats resolve in two
// or three calls instead of a few hundred.
const BULK_LIMIT = 100;

export async function getBulkDownloads(names) {
  // Scoped names are not accepted by the bulk endpoint, so they are dropped here;
  // callers that care about a specific scoped package should ask for it directly.
  const plain = [...new Set(names.filter((name) => !name.startsWith("@")))];
  const batches = [];
  for (let i = 0; i < plain.length; i += BULK_LIMIT) {
    batches.push(plain.slice(i, i + BULK_LIMIT));
  }

  const found = new Map();
  const responses = await Promise.all(
    batches.map((batch) =>
      getJson(`${DOWNLOADS_API}/point/last-week/${batch.join(",")}`).catch(() => ({})),
    ),
  );

  for (const response of responses) {
    // A single-name batch answers with a bare record rather than a keyed map.
    const entries = response?.package ? { [response.package]: response } : response;
    for (const [name, record] of Object.entries(entries ?? {})) {
      if (record) found.set(name, record.downloads ?? 0);
    }
  }
  return found;
}
