#!/usr/bin/env python3
"""Unpack a published npm tarball and report what is inside it.

This runs in the TrueForge sandbox, which is the point: it handles a tarball
published by a stranger, and if anything here goes wrong it goes wrong somewhere
isolated rather than on the reviewer's laptop.

It never executes the package. It downloads, unpacks, reads, and compares.

Standard library only, so it runs on any sandbox image with Python 3 and needs no
install step of its own -- which would be a poor look for a tool whose subject is
install steps.

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

# The download cap bounds *compressed* bytes. A hostile archive can be small and
# expand without limit, so extraction is bounded separately, by member count, by
# individual member size, and by cumulative decompressed bytes.
MAX_DOWNLOAD_BYTES = 80 * 1024 * 1024
MAX_MEMBERS = 5000
MAX_MEMBER_BYTES = 20 * 1024 * 1024
MAX_EXTRACTED_BYTES = 150 * 1024 * 1024

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES_SCANNED = 3000

SOURCE_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
COMPILABLE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".jsx", ".coffee")

# Shell and batch files are text. They were previously lumped in with compiled
# artifacts and skipped, which meant a postinstall calling install.sh containing
# `curl ... | bash` never reached the pattern that exists to catch exactly that.
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd")
BINARY_SUFFIXES = (".node", ".exe", ".dll", ".so", ".dylib", ".wasm", ".bin")

SCANNABLE_SUFFIXES = SOURCE_SUFFIXES + SCRIPT_SUFFIXES

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
}

SEVERITY_BY_CHECK = {
    "pipe_to_shell": "critical",
    "process_execution": "high",
    "raw_socket": "high",
    "dynamic_eval": "medium",
    "long_encoded_literal": "medium",
    "char_code_assembly": "medium",
}

# Environment reads are matched separately from the table above because the useful
# quantity is how many *distinct variables* a file touches, which means capturing
# the names. Both notations have to be captured: a regex that matches only the
# opening bracket collapses every process.env["..."] access into one value, and a
# file reading a dozen secrets that way would never cross the threshold.
ENV_ACCESS = re.compile(
    r"""process\.env\.([A-Za-z_$][\w$]*)|process\.env\[\s*['"]([^'"]+)['"]\s*\]"""
)
ENV_DISTINCT_THRESHOLD = 3

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
    """Extract a tar.gz, refusing members that would escape or exhaust the sandbox.

    A tarball is attacker-controlled input, in two different ways.

    It can try to write outside the destination -- a member named ../../.bashrc, an
    absolute path, or a symlink pointing at /etc/passwd. Every member is resolved
    against the destination and rejected if it escapes.

    It can also be a decompression bomb. The download cap only bounds compressed
    bytes, and a few megabytes of gzip expands to as much as the attacker likes, so
    member count, individual member size, and cumulative extracted bytes are all
    capped here. Hitting a cap stops extraction and is reported, never ignored: a
    partial unpack that looks like a complete one is exactly the kind of quiet
    failure this tool is supposed to expose.
    """
    destination = os.path.realpath(destination)
    extracted = 0
    total_bytes = 0
    truncated = None

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        for index, member in enumerate(tar):
            if index >= MAX_MEMBERS:
                truncated = f"Archive has more than {MAX_MEMBERS} members; extraction stopped."
                break
            if member.issym() or member.islnk():
                continue  # links are never needed to read a package's contents
            if not (member.isfile() or member.isdir()):
                continue
            if member.name.startswith("/") or os.path.isabs(member.name):
                continue

            target = os.path.realpath(os.path.join(destination, member.name))
            if target != destination and not target.startswith(destination + os.sep):
                continue  # path traversal attempt

            if member.isfile():
                if member.size > MAX_MEMBER_BYTES:
                    truncated = (
                        f"{member.name} is larger than {MAX_MEMBER_BYTES} bytes and was skipped."
                    )
                    continue
                if total_bytes + member.size > MAX_EXTRACTED_BYTES:
                    truncated = (
                        f"Unpacked size passed {MAX_EXTRACTED_BYTES} bytes; extraction stopped."
                    )
                    break
                total_bytes += member.size

            # `filter="data"` adds the interpreter's own hardening, but only exists on
            # Python 3.12+. The checks above are the ones this tool relies on, so an
            # older sandbox image degrades to those rather than failing outright.
            try:
                tar.extract(member, destination, filter="data")
            except TypeError:
                tar.extract(member, destination)

            if member.isfile():
                extracted += 1

    return {"files": extracted, "bytes": total_bytes, "truncated": truncated}


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


def has_shebang(full_path):
    try:
        with open(full_path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def looks_binary(full_path):
    """A NUL byte in the first block is the usual heuristic for "not text"."""
    try:
        with open(full_path, "rb") as handle:
            return 0 in handle.read(1024)
    except OSError:
        return False


def is_compilable(relative_path):
    """A .ts file is compilable source; a .d.ts is a type declaration and compiles to
    nothing. Counting declarations as evidence of a build step would let a plain
    JavaScript repository that merely ships typings be treated as built, which
    quietly downgrades every provenance finding against it."""
    lower = relative_path.lower()
    return lower.endswith(COMPILABLE_SUFFIXES) and not lower.endswith(DECLARATION_SUFFIXES)


def file_kind(relative_path, full_path):
    """Classify a file for scanning and comparison.

    Extension matching is case-insensitive, and files with no extension at all are
    classified by content. Both matter: npm bin entries routinely have no suffix,
    and a lifecycle hook running `sh install` does not care what the file is called.
    An allowlist of lowercase extensions would let either ship unexamined.
    """
    lower = relative_path.lower()
    if lower.endswith(DECLARATION_SUFFIXES):
        return "skip"
    if lower.endswith(SOURCE_SUFFIXES):
        return "source"
    if lower.endswith(SCRIPT_SUFFIXES):
        return "script"
    if lower.endswith(BINARY_SUFFIXES):
        return "binary"
    if "." not in relative_path.rsplit("/", 1)[-1]:
        if looks_binary(full_path):
            return "binary"
        if has_shebang(full_path):
            return "script"
    return "skip"


def is_build_path(relative_path):
    parts = set(relative_path.split("/")[:-1])
    return bool(parts & BUILD_DIR_PARTS) or relative_path.endswith((".min.js", ".min.mjs"))


def content_hash(path):
    """Hash a file with line endings normalised.

    git and npm disagree about newlines often enough that comparing raw bytes would
    report a difference between a repository checkout and a published tarball that
    are, as far as the code is concerned, identical.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_MEMBER_BYTES)
    except OSError:
        return None
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def stem_of(relative_path):
    name = relative_path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[0] if "." in name else name


def suffix_of(relative_path):
    name = relative_path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def check_manifest(root):
    """Lifecycle hooks and manifest-level facts. This is where install-time code lives.

    The manifest comes out of a hostile archive, so "valid JSON" is not the same as
    "an object with the shape npm expects". A top-level array, or a scripts member
    that is a list, must be reported rather than raising -- if this function throws,
    the tool dies without emitting the JSON report it promised, and a crafted
    package.json becomes a way to silence the audit.
    """
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

    if not isinstance(manifest, dict):
        findings.append(
            Finding(
                "manifest",
                "high",
                f"package.json is a {type(manifest).__name__}, not an object. npm would reject "
                "this, so it is malformed on purpose or the tarball is not a package.",
                path="package.json",
            )
        )
        return findings, {}

    scripts = manifest.get("scripts")
    if scripts is not None and not isinstance(scripts, dict):
        findings.append(
            Finding(
                "manifest",
                "medium",
                f'The "scripts" member is a {type(scripts).__name__}, not an object, so its '
                "lifecycle hooks could not be read.",
                path="package.json",
            )
        )
        scripts = {}
    scripts = scripts or {}

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
    """Static read of every source and shell file. No execution, ever."""
    findings = []
    scanned = 0
    truncated = False

    for relative, full in walk_files(root):
        if scanned >= MAX_FILES_SCANNED:
            truncated = True
            break

        kind = file_kind(relative, full)

        if kind == "binary":
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

        # Only executable source is scanned. package.json is the manifest check's job,
        # and .d.ts files never run, so a URL in one is a documentation link.
        if kind not in ("source", "script"):
            continue

        text = read_text(full)
        if text is None:
            continue
        scanned += 1
        build_path = is_build_path(relative)
        lines = text.splitlines()

        def cite(line_number):
            return lines[line_number - 1].strip() if 0 < line_number <= len(lines) else None

        for check, pattern in PATTERNS.items():
            # Minified bundles legitimately contain eval-ish and encoded content, so
            # inside a build directory only the unambiguous checks still apply.
            if build_path and check in {"long_encoded_literal", "dynamic_eval", "char_code_assembly"}:
                continue
            match = pattern.search(text)
            if not match:
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    check,
                    SEVERITY_BY_CHECK[check],
                    f"Matched the {check.replace('_', ' ')} pattern.",
                    path=relative,
                    line=line_number,
                    evidence=cite(line_number),
                )
            )

        # Reading one or two environment variables is what every library does to find
        # NODE_ENV. Several distinct values is collection.
        env_names = {name or bracketed for name, bracketed in ENV_ACCESS.findall(text)}
        if len(env_names) >= ENV_DISTINCT_THRESHOLD:
            match = ENV_ACCESS.search(text)
            line_number = text.count("\n", 0, match.start()) + 1 if match else None
            findings.append(
                Finding(
                    "env_harvest",
                    "low",
                    f"Reads {len(env_names)} distinct environment variables.",
                    path=relative,
                    line=line_number,
                    evidence=", ".join(sorted(env_names)[:10]),
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

    return findings, {"files_scanned": scanned, "scan_truncated": truncated}


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


def index_repository(repo_root):
    """Index the repository by path and by basename, with content hashes."""
    by_path = {}
    by_stem = {}
    is_built = False

    for relative, full in walk_files(repo_root):
        by_path[relative] = content_hash(full)
        by_stem.setdefault(stem_of(relative), []).append(relative)
        if relative.rsplit("/", 1)[-1] in BUILD_CONFIG_FILES:
            is_built = True
        if is_compilable(relative):
            is_built = True

    return by_path, by_stem, is_built


def compare_with_source(npm_root, repo_bytes):
    """Compare what ships against what was reviewed.

    The repository is what humans read; the tarball is what actually runs on their
    machines. Two things can go wrong, and both are reported:

      - a file that ships and has no counterpart in the repository at all
      - a file that ships at a path the repository also has, but with different
        contents

    The second is the one that is easy to miss. Indexing the repository and then
    only checking for the *presence* of a path would clear a modified index.js
    without ever looking at it, which is precisely the substitution an attacker
    would make.

    Where a file cannot be matched exactly, a counterpart is accepted only when it
    is unambiguous -- exactly one candidate. A basename shared by several files
    establishes nothing, and clearing a finding on that basis would let an injected
    index.js hide behind an unrelated index.ts.
    """
    findings = []
    with tempfile.TemporaryDirectory() as workspace:
        repo_extraction = safe_extract(repo_bytes, workspace)
        repo_root = package_root(workspace)
        by_path, by_stem, repo_is_built = index_repository(repo_root)

        # If the repository tree was itself truncated, "absent from the repository"
        # stops meaning anything -- the file may simply be past the cutoff. Findings
        # are still emitted, because staying silent would hide real ones, but none of
        # them can be claimed with confidence while the baseline is incomplete.
        repo_truncated = repo_extraction["truncated"]

        relocated = 0
        compiled_counterpart = 0

        def capped(severity):
            # Every provenance claim rests on the repository index being complete.
            # While it is not, none of them can be made with confidence -- including
            # the ones that come from finding a counterpart rather than missing one.
            return "low" if repo_truncated else severity

        def severity_for_missing(relative):
            if repo_truncated:
                return "low"
            # A plain-JavaScript package should mirror its repository, so an unmatched
            # file is close to damning. A project that compiles can rename on the way
            # out -- esbuild publishes lib/npm/node-install.ts as install.js -- and no
            # name-based rule tells that apart from a smuggled file. Build directories
            # are the likeliest place for legitimate generated code, so they are
            # quieter still. None of these are silent: a build directory is a naming
            # convention, not provenance, and dist/index.js is often the entry point.
            if not repo_is_built:
                return "medium" if is_build_path(relative) else "critical"
            return "low" if is_build_path(relative) else "medium"

        for relative, full in walk_files(npm_root):
            # Shell scripts get provenance too. A tarball-only install.sh is exactly
            # the file a lifecycle hook reaches for, and checking it only against a
            # handful of regexes while never asking whether it exists upstream would
            # leave the strongest finding in this tool unavailable against it.
            if file_kind(relative, full) not in ("source", "script"):
                continue

            published = content_hash(full)

            if relative in by_path:
                if by_path[relative] == published:
                    continue
                findings.append(
                    Finding(
                        "tarball_source_differs",
                        capped("medium" if repo_is_built else "high"),
                        "This file ships at the same path as one in the repository, but the "
                        "contents are not the same. Read both before accepting it."
                        + (
                            " The project has a build step, so a generated file may legitimately "
                            "differ from its checked-in form."
                            if repo_is_built
                            else " The project has no build step, so there is no ordinary reason "
                            "for the published copy to differ."
                        ),
                        path=relative,
                    )
                )
                continue

            candidates = by_stem.get(stem_of(relative), [])
            suffix = suffix_of(relative)
            same_kind = [c for c in candidates if suffix_of(c) == suffix]

            # Exactly one file of the same kind and name elsewhere in the tree: a
            # flattened publish layout. Content still has to agree.
            if len(same_kind) == 1:
                if by_path[same_kind[0]] == published:
                    relocated += 1
                    continue
                findings.append(
                    Finding(
                        "tarball_source_differs",
                        capped("medium" if repo_is_built else "high"),
                        f"Published as {relative}, which appears to correspond to "
                        f"{same_kind[0]} in the repository, but the contents differ.",
                        path=relative,
                    )
                )
                continue

            compilable = [c for c in candidates if is_compilable(c)]
            if repo_is_built and len(compilable) == 1:
                # Compiled output never matches its source byte for byte, so this
                # cannot be verified -- only noted, and at the lowest severity.
                compiled_counterpart += 1
                findings.append(
                    Finding(
                        "tarball_only_source",
                        "low",
                        f"Not present in the repository, but {compilable[0]} is a plausible "
                        "source for it. Compiled output cannot be verified by content, so this "
                        "correspondence is assumed from the name alone.",
                        path=relative,
                    )
                )
                continue

            findings.append(
                Finding(
                    "tarball_only_source",
                    severity_for_missing(relative),
                    "This file is published in the npm tarball but has no counterpart in the "
                    "linked repository at this version. Code that ships only in the tarball "
                    "has been reviewed by nobody."
                    + (
                        " It sits under a build directory, where generated code is expected."
                        if is_build_path(relative)
                        else ""
                    ),
                    path=relative,
                )
            )

        return findings, {
            "repo_files": len(by_path),
            "relocated_files": relocated,
            "compiled_from_source_files": compiled_counterpart,
            "repo_has_build_step": repo_is_built,
            "repo_tree_truncated": bool(repo_truncated),
            "repo_truncation_reason": repo_truncated,
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
            extraction = safe_extract(tarball, workspace)
        except Exception as error:  # noqa: BLE001
            report["error"] = f"Could not unpack the tarball: {error}"
            print(json.dumps(report, indent=2))
            return 1

        root = package_root(workspace)
        report["stats"]["files_extracted"] = extraction["files"]
        report["stats"]["unpacked_bytes"] = extraction["bytes"]
        if extraction["truncated"]:
            report["limitations"].append(extraction["truncated"])

        # Every stage is guarded. The archive is hostile by assumption, and a report
        # that says what could not be checked is worth more than a traceback.
        try:
            manifest_findings, _manifest = check_manifest(root)
            report["findings"].extend(manifest_findings)
        except Exception as error:  # noqa: BLE001
            report["limitations"].append(f"Manifest inspection failed: {error}")

        try:
            source_findings, scan_stats = scan_sources(root)
            report["findings"].extend(source_findings)
            report["stats"].update(scan_stats)
            if scan_stats["scan_truncated"]:
                report["limitations"].append(
                    f"Only the first {MAX_FILES_SCANNED} source files were scanned; the rest of "
                    "the package was not read. This report is not a complete pass."
                )
        except Exception as error:  # noqa: BLE001
            report["limitations"].append(f"Source scan failed: {error}")

        repo_bytes, reason = fetch_repo_tree(args.repo_url, args.version)
        if repo_bytes is None:
            report["limitations"].append(reason)
        else:
            try:
                diff_findings, diff_stats = compare_with_source(root, repo_bytes)
                report["findings"].extend(diff_findings)
                report["stats"].update(diff_stats)
                report["stats"]["compared_against_source"] = True
                if diff_stats.get("repo_tree_truncated"):
                    report["limitations"].append(
                        "The repository tree was only partially unpacked ("
                        f"{diff_stats['repo_truncation_reason']}), so absence from it is not "
                        "reliable evidence. Provenance findings are capped at low severity."
                    )
            except Exception as error:  # noqa: BLE001
                report["limitations"].append(f"Source comparison failed: {error}")

    report["stats"].setdefault("compared_against_source", False)
    report["summary"] = summarise(report["findings"])
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
