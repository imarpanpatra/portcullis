---
name: supply-chain-audit
description: Decide whether a third-party npm package is safe to admit into a repository. Use when asked to review, vet, audit, or approve adding a dependency, or when asked whether a package is safe or trustworthy. Covers unpacking the tarball in the sandbox, reading what is actually inside it, weighing that against registry signals, and reaching a verdict backed by evidence.
---

# Auditing an npm package before it enters a repository

Your job is to answer one question: **should this package be admitted?** Not "is it
popular", not "does it have vulnerabilities" — whether a careful engineer, shown
what you found, would let it in.

Two things make that answer trustworthy. You read the code that will actually run,
rather than the code the repository advertises. And every claim you make points at
a file and a line.

## The order of work

Do these in order. Later steps depend on what earlier ones return, and stopping
early is often correct.

### 1. Establish what you are looking at

Call `get_package_metadata`. You need the resolved version, the tarball URL, the
linked source repository, and whether the version declares lifecycle scripts.

If the package does not exist, say so and stop. Do not guess at a near name — a
mistyped package name is itself the thing you are guarding against.

### 2. Check whether the name is the attack

Call `find_impersonators` **before** you read any code. If the package sits one or
two edits from something with orders of magnitude more downloads, the most likely
explanation is that the user typed the wrong name.

When that happens, say so first and plainly: *"Did you mean `express`? The package
you named, `expres`, is a different package with 5,000 weekly downloads against
express's 132 million."* Ask before continuing. A user who typed a typo does not
want a security report; they want the typo pointed out.

### 3. Gather the registry signals

Call `get_download_stats` and `find_advisories`. Together with the metadata you
already have, weigh:

- **Age and cadence.** A package published days ago, or one that shipped a burst of
  releases in the last week after years of quiet, deserves more scrutiny. The
  second pattern is what a hijacked maintainer account looks like from outside.
- **Downloads against reputation.** A name that sounds official but has forty
  weekly downloads is a mismatch worth stating.
- **Maintainer count.** A single maintainer is not a finding on its own. It is
  context for everything else.
- **Advisories.** Note severity and whether a fixed version exists.

None of these condemn a package by themselves. They tell you how hard to look next.

### 4. Read what is actually in the tarball

This is the step nobody does by hand, and the reason you have a sandbox.

Run the bundled inspector **using Code Mode**, importing it rather than shelling
out. Do not use a shell command for this: the sandbox image is not guaranteed to
have `bash`, and a step that depends on one silently fails on some images. Python
is always present, because the harness runs its own client there.

```python
import sys, json
sys.path.insert(0, "/opt/tf/skills/supply-chain-audit/scripts")
from inspect_package import audit

report = audit(
    name="<package>",
    version="<version>",
    tarball_url="<tarball url from get_package_metadata>",
    repo_url="<repository_url from get_package_metadata, or None>",
)
print(json.dumps(report, indent=2))
```

It downloads the published tarball, unpacks it safely, and reports what is inside.
**It never executes the package.** It returns a dict rather than raising, so if
something could not be checked you get a `limitations` entry to report rather than
an error to work around.

Read the findings carefully; the checks that matter most are:

- **`install_script`** — a `preinstall`, `install`, or `postinstall` hook. This code
  runs on every machine that installs the package, including CI, before anyone has
  looked at anything. Always quote the command verbatim in your report. Most
  packages have no install hook at all; one that does needs a reason.
- **`tarball_only_source`** — a source file present in the published tarball that
  does not exist in the linked GitHub repository. This is the strongest signal in
  the whole audit. The repository is what humans review; the tarball is what runs.
  Code that exists only in the tarball was reviewed by nobody.
- **`obfuscation`** — long encoded literals, `eval`, `new Function`, dense hex
  escapes. Legitimate packages ship minified code in `dist/`; the inspector already
  accounts for that, so a hit outside a build directory is meaningful.
- **`process_execution`** and **`network_egress`** — `child_process`, raw sockets,
  or hardcoded hosts. In an install script these are close to disqualifying. In
  library code they may be the package's whole purpose. Judge by context.

### 5. Verify before you report

Every finding the inspector produces is a *candidate*. Before it reaches your
report, look at the evidence yourself and drop what does not hold up:

- A base64 blob in a package whose job is encoding is not obfuscation.
- A `postinstall` that runs `node-gyp rebuild` is a native module compiling, not an
  attack.
- A test fixture containing a fake key is not a leaked credential.

Read the surrounding lines before you keep a finding. **A false positive costs you
more than a missed low-severity issue** — an agent that cries wolf gets ignored,
and then the one real finding is ignored too.

### 6. Reach a verdict

Commit to one of three, and say which:

- **Admit** — nothing found that a careful reviewer would object to.
- **Admit with conditions** — safe enough, but pin the version, or use
  `--ignore-scripts`, or prefer a named alternative. State the condition.
- **Refuse** — say exactly which finding drives the refusal. One sentence.

Then render a Generative UI summary: the verdict, the signals as a small table
(age, downloads, maintainers, advisories, install hooks), and the findings ranked
by severity with their file and line.

## Auditing several packages at once

A reviewer adding a dependency is usually adding four. When you are handed more than
one, or handed a `package.json` to go through, **fan out**: one subagent per package,
each given the package name, the version, and the instruction to run the procedure
above and report its findings back.

The audits are genuinely independent -- what you learn about one package changes
nothing about another -- so running them in sequence makes the reviewer wait on the
slowest tarball for no reason at all. It also keeps each audit's raw tool output in
its own context instead of piling every packument into yours.

Merge what comes back into one report ranked by severity, and give **a verdict per
package**. Do not collapse them into a single answer for the set: admitting four and
refusing the fifth is the normal result, and a reviewer needs to know which is which.
If one subagent could not complete -- a tarball that would not download, a repository
that could not be read -- say so for that package rather than letting a gap disappear
into a summary.

## Admitting the package

Only after the user has seen the verdict, and only if they ask for it, add the
dependency through the GitHub tools: a branch, a change to `package.json`, and a
pull request whose body is your audit report.

**This write pauses for approval and that is deliberate.** Before it does, show the
user exactly what you intend: the branch name, the precise `package.json` change,
and the PR title. When the pause comes, they should be confirming something they
have already read, not discovering it.

If they deny it, do not look for another route to the same effect. Denial is an
answer. Acknowledge it and stop.

## Rules

- Never report a finding you have not read the evidence for.
- Never execute the package under audit. Unpack and read; that is all.
- Quote install-script commands verbatim. Never paraphrase them.
- Say "I could not check X" rather than implying you did. If the repository has no
  matching tag, the tarball-versus-source diff did not happen — report that as a
  gap, not as a clean result.
- Distinguish what you observed from what you infer. "This package runs a
  postinstall script that pipes a remote URL into bash" is an observation. "This
  package is malware" is an inference, and you should say which one you are making.
