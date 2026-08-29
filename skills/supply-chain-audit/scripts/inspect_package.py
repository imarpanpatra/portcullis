#!/usr/bin/env python3
"""Unpack a published npm tarball and report what is inside it.

This runs in the TrueForge sandbox, which is the point: it handles a tarball
published by a stranger, and if anything here goes wrong it goes wrong somewhere
isolated rather than on the reviewer's laptop.

It never executes the package. It downloads, unpacks, reads, and compares.

Standard library only, so it runs on any sandbox image with Python 3 and needs no
install step of its own -- which would be a poor look for a tool whose whole
subject is install steps.

Usage:
    python3 inspect_package.py --name express --version 5.2.1 \
        --tarball https://registry.npmjs.org/express/-/express-5.2.1.tgz \
        --repo-url https://github.com/expressjs/express
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

USER_AGENT = "portcullis-inspector"
NETWORK_TIMEOUT = 30
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES_SCANNED = 3000

SOURCE_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
COMPILABLE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".jsx", ".coffee")
EXECUTABLE_SUFFIXES = (".node", ".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".ps1", ".cmd")

# Minified bundles in a build directory are normal and would otherwise dominate the
# obfuscation checks, so those paths are held to a looser standard.
BUILD_DIR_PARTS = {"dist", "build", "umd", "esm", "cjs", "lib", "out", "bundle", "vendor"}

INSTALL_HOOKS = ("preinstall", "install", "postinstall")

# Presence of any of these means the published files need not mirror the repository.
BUILD_CONFIG_FILES = {
    "tsconfig.json", "rollup.config.js", "rollup.config.mjs", "webpack.config.js",
    "vite.config.js", "vite.config.ts", "babel.config.js", ".babelrc", "gulpfile.js",
}

PATTERNS = {
    "long_encoded_literal": re.compile(r"""["'][A-Za-z0-9+/]{200,}={0,2}["']"""),
    "dynamic_eval": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
    "char_code_assembly": re.compile(r"String\.fromCharCode\s*\("),
    "process_execution": re.compile(
        r"""require\s*\(\s*['"]child_process['"]|from\s+['"]child_process['"]"""
    ),
    "raw_socket": re.compile(
        r"""require\s*\(\s*['"](net|dgram|tls|dns)['"]|from\s+['"](net|dgram|tls|dns)['"]"""
    ),
    "pipe_to_shell": re.compile(r"(curl|wget)\b[^\n]{0,100}\|\s*(bash|sh|node|python)"),
    "env_harvest": re.compile(r"process\.env\s*(\[|\.[A-Z_]{3,})"),
}

HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
URL_LITERAL = re.compile(r"https?://([a-zA-Z0-9.\-]+)")

# Hosts a package can legitimately contact without it meaning anything.
BENIGN_HOSTS = {
    "registry.npmjs.org", "npmjs.org", "www.npmjs.com", "github.com", "www.github.com",
    "raw.githubusercontent.com", "codeload.github.com", "nodejs.org", "opensource.org",
    "www.apache.org", "json-schema.org", "www.w3.org", "schema.org", "localhost",
    "example.com", "www.example.com", "developer.mozilla.org", "tools.ietf.org",
}


class Finding(dict):
    """A single observation, shaped for the agent to reason over and cite."""

    def __init__(self, check, severity, detail, path=None, line=None, evidence=None):
        super().__init__(
            check=check,
            severity=severity,
            detail=detail,
            path=path,
            line=line,
            evidence=(evidence[:300] if evidence else None),
        )


def fetch(url):
    """Download a URL into memory, refusing anything implausibly large."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"Download exceeded {MAX_DOWNLOAD_BYTES} bytes: {url}")
    return data


def safe_extract(archive_bytes, destination):
    """Extract a tar.gz, refusing members that would write outside the destination.

    A tarball is attacker-controlled input. A member named ../../.bashrc, or an
    absolute path, or a symlink pointing outside the tree, would let the archive
    write wherever it liked -- and this tool exists precisely because the archive
    may be hostile. Every member is resolved and checked before extraction.
    """
    destination = os.path.realpath(destination)
    extracted = 0

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk():
                continue  # links are never needed to read a package's contents
            if not (member.isfile() or member.isdir()):
                continue
            if member.name.startswith("/") or os.path.isabs(member.name):
                continue

            target = os.path.realpath(os.path.join(destination, member.name))
            if target != destination and not target.startswith(destination + os.sep):
                continue  # path traversal attempt

            # `filter="data"` adds the interpreter's own hardening, but only exists on
            # Python 3.12+. The checks above are the ones this tool relies on, so an
            # older sandbox image degrades to those rather than failing outright.
            try:
                tar.extract(member, destination, filter="data")
            except TypeError:
                tar.extract(member, destination)

            if member.isfile():
                extracted += 1

    return extracted


def package_root(directory):
    """npm tarballs nest everything under `package/`; repo tarballs under a slug."""
    entries = [e for e in os.listdir(directory) if not e.startswith(".")]
    if len(entries) == 1:
        candidate = os.path.join(directory, entries[0])
        if os.path.isdir(candidate):
            return candidate
    return directory


def walk_files(root):
    """Relative paths of every file under root, skipping node_modules and VCS dirs."""
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git"}]
        for name in names:
            full = os.path.join(base, name)
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def is_build_path(relative_path):
    parts = set(relative_path.split("/")[:-1])
    return bool(parts & BUILD_DIR_PARTS) or relative_path.endswith((".min.js", ".min.mjs"))


def sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def check_manifest(root):
    """Lifecycle hooks and manifest-level facts. This is where install-time code lives."""
    findings = []
    manifest_path = os.path.join(root, "package.json")
    raw = read_text(manifest_path)
    if raw is None:
        findings.append(Finding("manifest", "high", "The tarball has no readable package.json."))
        return findings, {}

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as error:
        findings.append(Finding("manifest", "high", f"package.json does not parse: {error}"))
        return findings, {}

    scripts = manifest.get("scripts") or {}
    for hook in INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str):
            continue
        # node-gyp is how native modules build; it is the one common benign case.
        native_build = "node-gyp" in command or "prebuild-install" in command
        findings.append(
            Finding(
                "install_script",
                "medium" if native_build else "high",
                f"Declares a {hook} script, which runs on every machine that installs "
                f"this package, before any code is reviewed."
                + (" Looks like a native module build." if native_build else ""),
                path="package.json",
                evidence=f"{hook}: {command}",
            )
        )

    if manifest.get("bin"):
        findings.append(
            Finding(
                "declares_binary",
                "low",
                "Installs an executable onto PATH.",
                path="package.json",
                evidence=json.dumps(manifest.get("bin"))[:200],
            )
        )

    return findings, manifest


def scan_sources(root):
    """Static read of every source file. No execution, ever."""
    findings = []
    scanned = 0

    for relative, full in walk_files(root):
        if scanned >= MAX_FILES_SCANNED:
            break

        if relative.endswith(EXECUTABLE_SUFFIXES):
            findings.append(
                Finding(
                    "binary_artifact",
                    "medium",
                    "Ships a compiled or executable file, whose contents cannot be reviewed "
                    "by reading the package.",
                    path=relative,
                )
            )
            continue

        # Only executable source is scanned. package.json is covered by check_manifest,
        # and running the egress and eval patterns over it just reports the homepage
        # and bug-tracker URLs every package declares. Type declarations are skipped
        # for the same reason: nothing in a .d.ts ever runs, so a URL in one is a
        # documentation link, not egress.
        if not relative.endswith(SOURCE_SUFFIXES) or relative.endswith(DECLARATION_SUFFIXES):
            continue

        text = read_text(full)
        if text is None:
            continue
        scanned += 1
        build_path = is_build_path(relative)
        lines = text.splitlines()

        for check, pattern in PATTERNS.items():
            # Minified bundles legitimately contain eval-ish and encoded content, so
            # inside a build directory only the unambiguous checks still apply.
            if build_path and check in {"long_encoded_literal", "dynamic_eval", "char_code_assembly"}:
                continue

            # Reading one or two environment variables is what every library does to
            # find NODE_ENV. Only a file pulling several distinct values is doing
            # something that looks like collection.
            if check == "env_harvest" and len(set(pattern.findall(text))) < 3:
                continue

            match = pattern.search(text)
            if not match:
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            severity = {
                "pipe_to_shell": "critical",
                "process_execution": "high",
                "raw_socket": "high",
                "dynamic_eval": "medium",
                "long_encoded_literal": "medium",
                "char_code_assembly": "medium",
                "env_harvest": "low",
            }[check]
            findings.append(
                Finding(
                    check,
                    severity,
                    f"Matched the {check.replace('_', ' ')} pattern.",
                    path=relative,
                    line=line_number,
                    evidence=lines[line_number - 1].strip() if line_number <= len(lines) else None,
                )
            )

        if not build_path:
            hex_hits = len(HEX_ESCAPE.findall(text))
            if hex_hits >= 50:
                findings.append(
                    Finding(
                        "obfuscation",
                        "high",
                        f"Contains {hex_hits} hex escape sequences outside a build directory, "
                        "which is how string literals are usually hidden.",
                        path=relative,
                    )
                )

        hosts = {h.lower() for h in URL_LITERAL.findall(text)} - BENIGN_HOSTS
        if hosts and not build_path:
            findings.append(
                Finding(
                    "network_egress",
                    "medium",
                    "References hosts that are not the registry, GitHub, or a documentation site.",
                    path=relative,
                    evidence=", ".join(sorted(hosts)[:8]),
                )
            )

    return findings, scanned


def repo_slug(repo_url):
    match = re.search(r"github\.com[/:]([^/]+)/([^/#?]+)", repo_url or "")
    if not match:
        return None
    return match.group(1), match.group(2).removesuffix(".git")


def fetch_repo_tree(repo_url, version):
    """Download the GitHub source for this exact version.

    Only a tag that matches the version is acceptable. Comparing a tarball against
    the repository's default branch would produce differences that mean nothing --
    the branch has moved on since the release -- and a check that reports noise is
    worse than no check.
    """
    slug = repo_slug(repo_url)
    if not slug:
        return None, "The package does not link to a GitHub repository."
    owner, repo = slug

    for ref in (f"refs/tags/v{version}", f"refs/tags/{version}"):
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"
        try:
            return fetch(url), None
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
            continue

    return None, (
        f"No tag matching version {version} was found in {owner}/{repo}, so the published "
        "tarball could not be compared against reviewed source."
    )


def compare_with_source(npm_root, repo_bytes):
    """Files that exist in the published tarball but not in the reviewed repository.

    This is the check that matters most. The repository is what humans read; the
    tarball is what actually runs on their machines. Anything present only in the
    tarball was reviewed by nobody.

    Build output legitimately exists only in the tarball, so those paths are
    reported as information rather than as findings.
    """
    findings = []
    with tempfile.TemporaryDirectory() as workspace:
        safe_extract(repo_bytes, workspace)
        repo_root = package_root(workspace)

        repo_files = {}
        repo_stems = set()
        repo_is_built = False
        for relative, full in walk_files(repo_root):
            repo_files[relative] = sha256(full)
            if relative.rsplit("/", 1)[-1] in BUILD_CONFIG_FILES:
                repo_is_built = True
            if relative.endswith(COMPILABLE_SUFFIXES):
                repo_is_built = True
                # A published foo.js compiled from a reviewed foo.ts is build output,
                # not unreviewed code. Match on basename rather than full path: the
                # npm package is often assembled from a subdirectory of the repo, so
                # a tarball's install.js can correspond to npm/pkg/install.ts and the
                # paths will never line up.
                repo_stems.add(relative.rsplit(".", 1)[0].rsplit("/", 1)[-1])

        # Match on basename-and-suffix as well as exact path: npm tarballs often flatten
        # a `src/` prefix away, and treating that as "missing from the repo" would be
        # a false positive on nearly every package.
        repo_tails = {r.split("/", 1)[-1] for r in repo_files}

        build_only = 0
        compiled_from_source = 0
        for relative, full in walk_files(npm_root):
            if not relative.endswith(SOURCE_SUFFIXES):
                continue
            tail = relative.split("/", 1)[-1]
            if relative in repo_files or tail in repo_tails or relative in repo_tails:
                continue
            if is_build_path(relative):
                build_only += 1
                continue
            if relative.rsplit(".", 1)[0].rsplit("/", 1)[-1] in repo_stems:
                compiled_from_source += 1
                continue
            # How much this finding is worth depends on whether the project compiles.
            # In a plain-JavaScript package the tarball should mirror the repository,
            # so a file present in one and not the other is close to damning. A project
            # that builds can legitimately rename as it publishes -- esbuild ships
            # lib/npm/node-install.ts as install.js -- and no name-based rule can tell
            # that apart from a smuggled file. So it is reported either way, but only
            # claimed as critical where the claim actually holds.
            findings.append(
                Finding(
                    "tarball_only_source",
                    "medium" if repo_is_built else "critical",
                    "This source file is published in the npm tarball but has no counterpart "
                    "in the linked repository at this version. Code that ships only in the "
                    "tarball has been reviewed by nobody."
                    + (
                        " The repository has a build step, so the file may simply have been "
                        "renamed during compilation. Read it and find its source before "
                        "treating this as an attack."
                        if repo_is_built
                        else " The repository has no build step, so the tarball should mirror "
                        "it. There is no ordinary reason for this file to exist."
                    ),
                    path=relative,
                )
            )

        return findings, {
            "repo_files": len(repo_files),
            "build_only_files": build_only,
            "compiled_from_source_files": compiled_from_source,
            "repo_has_build_step": repo_is_built,
        }


def summarise(findings):
    order = ["critical", "high", "medium", "low"]
    counts = {level: 0 for level in order}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    highest = next((level for level in order if counts[level]), None)
    return {"counts": counts, "highest_severity": highest, "total": len(findings)}


def main():
    parser = argparse.ArgumentParser(description="Inspect a published npm tarball.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tarball", required=True, help="Tarball URL from get_package_metadata.")
    parser.add_argument("--repo-url", default=None, help="Linked source repository, if any.")
    args = parser.parse_args()

    report = {
        "package": args.name,
        "version": args.version,
        "findings": [],
        "limitations": [],
        "stats": {},
    }

    try:
        tarball = fetch(args.tarball)
    except Exception as error:  # noqa: BLE001 - the agent needs the reason, not a traceback
        report["error"] = f"Could not download the tarball: {error}"
        print(json.dumps(report, indent=2))
        return 1

    report["stats"]["tarball_bytes"] = len(tarball)

    with tempfile.TemporaryDirectory() as workspace:
        try:
            extracted = safe_extract(tarball, workspace)
        except Exception as error:  # noqa: BLE001
            report["error"] = f"Could not unpack the tarball: {error}"
            print(json.dumps(report, indent=2))
            return 1

        root = package_root(workspace)
        report["stats"]["files_extracted"] = extracted

        manifest_findings, _manifest = check_manifest(root)
        report["findings"].extend(manifest_findings)

        source_findings, scanned = scan_sources(root)
        report["findings"].extend(source_findings)
        report["stats"]["files_scanned"] = scanned

        repo_bytes, reason = fetch_repo_tree(args.repo_url, args.version)
        if repo_bytes is None:
            report["limitations"].append(reason)
        else:
            try:
                diff_findings, diff_stats = compare_with_source(root, repo_bytes)
                report["findings"].extend(diff_findings)
                report["stats"].update(diff_stats)
                report["stats"]["compared_against_source"] = True
            except Exception as error:  # noqa: BLE001
                report["limitations"].append(f"Source comparison failed: {error}")

    if "compared_against_source" not in report["stats"]:
        report["stats"]["compared_against_source"] = False

    report["summary"] = summarise(report["findings"])
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
