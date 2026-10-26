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

    def misses(self, text: str, at: str = "README.md") -> list[str]:
        md = self.root / at
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(text)
        return doclinks.broken(md, self.root)

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

    def test_a_target_outside_the_repository_is_reported(self) -> None:
        misses = self.misses("[out](../../etc/hosts)\n")
        self.assertEqual(len(misses), 1)
        self.assertIn("outside the repository", misses[0])


if __name__ == "__main__":
    unittest.main()
