#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/doclinks.py. Run: python3 scripts/test_doclinks.py"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("doclinks", _HERE / "doclinks.py")
doclinks = importlib.util.module_from_spec(_spec)
sys.modules["doclinks"] = doclinks
_spec.loader.exec_module(doclinks)


class Broken(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name).resolve()
        (self.root / "docs").mkdir()
        (self.root / "docs" / "guide.md").write_text("# Guide\n")
        (self.root / "img.png").write_bytes(b"")

    def tearDown(self) -> None:
        self._dir.cleanup()

    def present(self) -> set[str]:
        """Every path in the tree, named as the directory lists it."""
        return {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")}

    def misses(self, text: str, at: str = "README.md", present: set[str] | None = None) -> list[str]:
        md = self.root / at
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(text)
        return doclinks.broken(md, self.root, self.present() if present is None else present)

    def test_a_link_to_a_missing_file_is_reported_with_its_line(self) -> None:
        self.assertEqual(
            self.misses("ok\n[gone](docs/missing.md)\n"),
            ["README.md:2: docs/missing.md"],
        )

    def test_present_targets_pass_in_every_form(self) -> None:
        text = (
            "[a](docs/guide.md) [b](./docs/guide.md#guide) [c](docs/guide.md?plain=1)\n"
            "[d](docs/) [e](/img.png)\n"
            "[ref]: docs/guide.md\n"
            '<img src="img.png" alt="x"> <a href="docs/guide.md">g</a>\n'
        )
        self.assertEqual(self.misses(text), [])

    def test_a_link_is_resolved_from_the_file_that_holds_it(self) -> None:
        self.assertEqual(self.misses("[up](../img.png)\n", at="docs/page.md"), [])
        self.assertEqual(
            self.misses("[same](img.png)\n", at="docs/page.md"),
            ["docs/page.md:1: img.png"],
        )

    def test_reference_definitions_and_html_attributes_are_checked(self) -> None:
        self.assertEqual(
            self.misses('[ref]: nowhere.md\n<img src="none.png">\n'),
            ["README.md:1: nowhere.md", "README.md:2: none.png"],
        )

    def test_external_urls_and_bare_anchors_are_not_checked(self) -> None:
        text = "[w](https://example.invalid/x) [m](mailto:a@example.invalid) [s](#section)\n"
        self.assertEqual(self.misses(text), [])

    def test_code_is_not_read_for_links(self) -> None:
        text = (
            "`[span](missing.md)`\n"
            "```\n[fenced](missing.md)\n```\n"
            "~~~~\n```\n[still fenced](missing.md)\n~~~~\n"
            "[after](missing.md)\n"
        )
        self.assertEqual(self.misses(text), ["README.md:9: missing.md"])

    def test_a_fence_closes_only_on_its_own_character_at_its_length_or_longer(self) -> None:
        text = (
            "~~~\n````\n[in](missing.md)\n~~~\n"
            "````\n```\n[in](missing.md)\n````\n"
            "[after](missing.md)\n"
        )
        self.assertEqual(self.misses(text), ["README.md:9: missing.md"])

    def test_a_root_relative_link_resolves_from_the_root_in_any_directory(self) -> None:
        self.assertEqual(self.misses("[r](/img.png)\n", at="docs/page.md"), [])

    def test_a_changelog_fragment_resolves_from_the_root_its_entry_is_copied_to(self) -> None:
        at = "changelog.d/fixed-thing.md"
        self.assertEqual(self.misses("[g](docs/guide.md)\n", at=at), [])
        self.assertIn("outside", self.misses("[g](../docs/guide.md)\n", at=at)[0])
        self.assertEqual(self.misses("[g](../docs/guide.md)\n", at="changelog.d/README.md"), [])

    def test_a_path_present_on_disk_but_not_to_git_does_not_satisfy_a_link(self) -> None:
        self.assertEqual(
            self.misses("[g](docs/Guide.md)\n"),
            ["README.md:1: docs/Guide.md"],
            "a case-insensitive disk finds docs/guide.md; git does not",
        )
        unlisted = self.present() - {"img.png"}
        self.assertEqual(self.misses("[i](img.png)\n", present=unlisted), ["README.md:1: img.png"])

    def test_footnotes_and_link_titles_are_read_as_markdown_has_them(self) -> None:
        text = "[^1]: some note\n[a](docs/guide.md 'T') [b](docs/guide.md (T)) [c](gone.md 'T')\n"
        self.assertEqual(self.misses(text), ["README.md:2: gone.md"])

    def test_a_template_under_github_links_by_url(self) -> None:
        at = ".github/ISSUE_TEMPLATE/bug.md"
        self.assertIn("link by URL", self.misses("[a](../../docs/guide.md)\n", at=at)[0])
        url = "[a](https://github.com/o/r/blob/main/docs/guide.md)\n"
        self.assertEqual(self.misses(url, at=at), [])

    def test_a_tracked_file_missing_from_the_working_tree_is_reported(self) -> None:
        gone = self.root / "docs" / "moved.md"
        self.assertEqual(
            doclinks.check([gone], self.root, self.present()),
            ["docs/moved.md: tracked, but missing from the working tree"],
        )

    def test_a_target_outside_the_repository_is_reported(self) -> None:
        misses = self.misses("[out](../../etc/hosts)\n")
        self.assertEqual(len(misses), 1)
        self.assertIn("outside the repository", misses[0])


if __name__ == "__main__":
    unittest.main()
