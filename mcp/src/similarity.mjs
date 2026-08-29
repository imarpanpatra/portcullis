// Typosquat detection. An attacker publishes `expres` or `lodahs` and waits for a
// typo. The signal is not the similar name on its own -- plenty of legitimate
// packages have near-neighbours -- it is a name one or two edits away from a
// package with orders of magnitude more downloads.

// Damerau-Levenshtein, which unlike plain Levenshtein counts a transposition
// (`recieve` for `receive`) as one edit rather than two. Typos are usually
// transpositions, so the distinction matters here.
export function editDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const rows = a.length + 1;
  const cols = b.length + 1;
  const d = Array.from({ length: rows }, (_, i) => {
    const row = new Array(cols).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j < cols; j += 1) d[0][j] = j;

  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }
  return d[a.length][b.length];
}

// Scope and punctuation are noise for this comparison: `@acme/left-pad` and
// `leftpad` should read as near-identical, because to a hurried human they are.
export function normalise(name) {
  return name.replace(/^@[^/]+\//, "").replace(/[-_.]/g, "").toLowerCase();
}

const MAX_EDITS = 2;
const POPULARITY_RATIO = 100;

/**
 * Rank candidates against the queried package. A candidate is suspicious when it
 * is within MAX_EDITS of the query and dwarfs it in downloads -- that is the
 * shape of a typosquat sitting next to the package it impersonates.
 */
export function rankNeighbours(queryName, queryDownloads, candidates) {
  const query = normalise(queryName);

  return candidates
    .filter((candidate) => candidate.name !== queryName)
    .map((candidate) => {
      const distance = editDistance(query, normalise(candidate.name));
      const ratio = queryDownloads > 0 ? candidate.weekly_downloads / queryDownloads : Infinity;
      return {
        name: candidate.name,
        weekly_downloads: candidate.weekly_downloads,
        edit_distance: distance,
        downloads_vs_query: Number.isFinite(ratio) ? Math.round(ratio) : null,
        impersonation_suspected: distance > 0 && distance <= MAX_EDITS && ratio >= POPULARITY_RATIO,
      };
    })
    .filter((candidate) => candidate.edit_distance <= MAX_EDITS + 1)
    .sort((a, b) => a.edit_distance - b.edit_distance || b.weekly_downloads - a.weekly_downloads);
}

// Searching the registry for a typo does not reliably surface the package being
// impersonated -- ask npm for "expres" and "express" is nowhere in the results. So
// rather than hoping search finds the victim, generate the names an attacker would
// plausibly have registered and probe for them directly.

const HOMOGLYPHS = [
  ["l", "1"], ["l", "i"], ["i", "1"], ["o", "0"], ["s", "5"],
  ["e", "3"], ["a", "4"], ["u", "v"], ["m", "rn"], ["c", "k"],
];

const AFFIXES = (base) => [
  `node-${base}`, `node_${base}`, `${base}-js`, `${base}js`, `${base}.js`,
  `${base}2`, `${base}-node`, `js-${base}`,
];

const MAX_CANDIDATES = 200;

/**
 * Names within striking distance of this one: single-character deletions,
 * adjacent transpositions, doubled letters, separator variants, homoglyph swaps,
 * and the usual affix dressing. Caller probes these against the registry; the ones
 * that exist are the neighbourhood.
 */
export function generateNeighbours(name) {
  const base = name.replace(/^@[^/]+\//, "").toLowerCase();
  const out = new Set();

  for (let i = 0; i < base.length; i += 1) {
    out.add(base.slice(0, i) + base.slice(i + 1)); // deletion
    out.add(base.slice(0, i) + base[i] + base.slice(i)); // duplication
    if (i < base.length - 1) {
      out.add(base.slice(0, i) + base[i + 1] + base[i] + base.slice(i + 2)); // transposition
    }
  }

  out.add(base.replace(/[-_.]/g, ""));
  out.add(base.replace(/-/g, "_"));
  out.add(base.replace(/_/g, "-"));

  for (const [from, to] of HOMOGLYPHS) {
    if (base.includes(from)) out.add(base.replaceAll(from, to));
    if (base.includes(to)) out.add(base.replaceAll(to, from));
  }

  for (const affix of AFFIXES(base)) out.add(affix);

  // The unscoped form of a scoped package, which is the classic way to sit beside
  // an official @org package and catch anyone who drops the scope.
  out.add(base);
  out.delete(name.toLowerCase());

  return [...out].filter((candidate) => candidate.length > 0).slice(0, MAX_CANDIDATES);
}
