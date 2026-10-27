#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail when a relative link in a tracked Markdown file names a path that does not exist.

A broken link is a claim about the repository that stopped being true, and a sweep that
reads sentences for truth does not see it. This reads every tracked `*.md`, takes each
inline link `[text](target)`, reference definition `[label]: target` and HTML `href`/`src`,
and checks the path a relative target names, resolved from the file that holds it. A changelog
fragment is copied into the root CHANGELOG.md at release, so its links resolve from the root.
An issue or pull request template under `.github/` is shown in the body of an issue or
pull request, where a relative link does not resolve, so a relative link there is reported:
it links by URL. A path counts as present when git carries it, tracked or untracked and not ignored, in exactly
that case: a case-insensitive disk or a build output must not pass a link CI would reject.

Not checked, on purpose: URLs with a scheme (`https:`, `mailto:` and the like), a target
that is only an `#anchor`, the anchor or query after a path, and anything inside a fenced
code block or an inline code span, and footnote definitions. External URLs would make the
gate fail for reasons that have nothing to do with the change. A target that climbs out of the
repository is reported, since no file here can satisfy it, and so is a tracked Markdown file
missing from the working tree. The Markdown is read with patterns, not a parser; forms this
repository does not use (angle-bracketed targets with spaces, indented code, reference
definitions inside block quotes) are not handled.

Usage: python3 scripts/doclinks.py check
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")
_INLINE = re.compile(r"""\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)""")
_REFERENCE = re.compile(r"^\s{0,3}\[(?!\^)[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
_HTML = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"']+)["']""")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def targets(text: str) -> list[tuple[int, str]]:
    """Each (line number, link target) in `text`, outside code."""
    found: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        opened = _FENCE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence):
                fence = None
            continue
        if opened:
            fence = opened.group(1)
            continue
        prose = _CODE_SPAN.sub("", line)
        for pattern in (_INLINE, _HTML):
            found.extend((number, m.group(1)) for m in pattern.finditer(prose))
        reference = _REFERENCE.match(prose)
        if reference:
            found.append((number, reference.group(1)))
    return found


def is_fragment(md: Path, root: Path) -> bool:
    """A changelog fragment, which `changelog.sh --release` copies into the root CHANGELOG.md."""
    return md.parent == root / "changelog.d" and md.name != "README.md"


def is_template(md: Path, root: Path) -> bool:
    """An issue or pull request template, shown in a body where relative links do not resolve."""
    return md.is_relative_to(root / ".github")


def broken(md: Path, root: Path, present: set[str]) -> list[str]:
    """`file:line: target` for each relative target in `md` that names no path in `present`."""
    out = []
    root = root.resolve()
    for number, target in targets(md.read_text(encoding="utf-8")):
        if _SCHEME.match(target) or target.startswith("#"):
            continue
        path = target.split("#", 1)[0].split("?", 1)[0]
        if not path:
            continue
        base = root if path.startswith("/") or is_fragment(md, root) else md.parent
        resolved = (base / path.lstrip("/")).resolve()
        where = f"{md.relative_to(root)}:{number}: {target}"
        if is_template(md, root):
            out.append(f"{where} (shown in an issue or pull request; link by URL)")
        elif not resolved.is_relative_to(root):
            out.append(f"{where} (outside the repository)")
        elif resolved != root and resolved.relative_to(root).as_posix() not in present:
            out.append(where)
    return out


def git_files(root: Path, *args: str) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", *args],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return [name for name in listed.split("\0") if name]


def present_paths(root: Path = ROOT) -> set[str]:
    """Every path git carries, tracked or untracked and not ignored, and every directory
    above one."""
    out: set[str] = set()
    for name in git_files(root, "--cached", "--others", "--exclude-standard"):
        parts = name.split("/")
        out.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    return out


def check(files: list[Path], root: Path, present: set[str]) -> list[str]:
    """Every miss in `files`: each broken link, and each file missing from the working tree."""
    misses = []
    for md in files:
        if not md.is_file():
            misses.append(f"{md.relative_to(root)}: tracked, but missing from the working tree")
            continue
        misses.extend(broken(md, root, present))
    return misses


def main(argv: list[str]) -> int:
    if argv != ["check"]:
        sys.stderr.write("usage: python3 scripts/doclinks.py check\n")
        return 2
    files = [ROOT / name for name in git_files(ROOT, "--", "*.md")]
    misses = check(files, ROOT, present_paths())
    for miss in misses:
        print(miss)
    if misses:
        print(f"{len(misses)} broken link(s) in {len(files)} Markdown files")
        return 1
    print(f"doclinks: ok ({len(files)} Markdown files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
