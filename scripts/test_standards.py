#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/standards.py. Run: python3 scripts/test_standards.py"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("standards", _HERE / "standards.py")
standards = importlib.util.module_from_spec(_spec)
sys.modules["standards"] = standards
_spec.loader.exec_module(standards)

SAMPLE = """\
# A full-line comment is not part of any value.
rule: >-
  Read the spec.
  Then change it.

non_surface:
  - crates/decern-server/src/main.rs

standards:
  - name: Example (RFC 0000)
    url: https://example.invalid/rfc0000
    verified: 2026-01-02
    surface:
      - crates/decern-server/src/jose.rs
      - crates/decern-proof/src/
    conformance: >-
      Line one
      # a comment line inside a block
      line two.

  - name: Pinned thing
    url: https://example.invalid/pinned
    verified: pinned
    surface:
      - crates/decern-proof/src/
    conformance: >-
      Pinned.
"""


def run_check(reg) -> tuple[int, str]:
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = standards.cmd_check(reg)
    return code, err.getvalue()


class Parse(unittest.TestCase):
    def test_rule_non_surface_and_entries(self):
        reg = standards._parse_registry(SAMPLE)
        self.assertEqual(reg.rule, "Read the spec. Then change it.")
        self.assertEqual(reg.non_surface, ["crates/decern-server/src/main.rs"])
        self.assertEqual([s.name for s in reg.standards], ["Example (RFC 0000)", "Pinned thing"])
        first = reg.standards[0]
        self.assertEqual(first.url, "https://example.invalid/rfc0000")
        self.assertEqual(first.verified, "2026-01-02")
        self.assertEqual(
            first.surface, ["crates/decern-server/src/jose.rs", "crates/decern-proof/src/"]
        )
        self.assertEqual(first.conformance, "Line one line two.")
        self.assertEqual(reg.standards[1].verified, "pinned")

    def test_non_surface_after_standards_stays_its_own_block(self):
        moved = SAMPLE.replace(
            "non_surface:\n  - crates/decern-server/src/main.rs\n\n", ""
        ) + "\nnon_surface:\n  - crates/decern-server/src/main.rs\n"
        reg = standards._parse_registry(moved)
        self.assertEqual(reg.non_surface, ["crates/decern-server/src/main.rs"])
        self.assertEqual(reg.standards[-1].surface, ["crates/decern-proof/src/"])
        self.assertEqual(reg.standards[-1].conformance, "Pinned.")

    def test_a_registry_without_standards_is_refused(self):
        with self.assertRaises(SystemExit):
            standards._parse_registry("rule: >-\n  x\n")


class Check(unittest.TestCase):
    def test_the_registry_in_the_tree_passes(self):
        self.assertEqual(run_check(standards.load()), (0, ""))

    def assert_refused(self, mutate, needle):
        reg = standards.load()
        mutate(reg)
        code, err = run_check(reg)
        self.assertEqual(code, 1, err)
        self.assertIn(needle, err)

    def test_missing_url(self):
        self.assert_refused(lambda r: setattr(r.standards[0], "url", ""), "missing url")

    def test_missing_verified(self):
        self.assert_refused(
            lambda r: setattr(r.standards[0], "verified", None), "missing verified"
        )

    def test_verified_that_is_not_a_date(self):
        self.assert_refused(
            lambda r: setattr(r.standards[0], "verified", "2026-13-40"), "not YYYY-MM-DD"
        )

    def test_duplicate_name(self):
        def dup(r):
            r.standards[1].name = r.standards[0].name

        self.assert_refused(dup, "duplicate standard name")

    def test_empty_surface(self):
        self.assert_refused(lambda r: setattr(r.standards[0], "surface", []), "empty surface")

    def test_surface_path_that_does_not_exist(self):
        self.assert_refused(
            lambda r: r.standards[0].surface.append("crates/nowhere.rs"), "surface path missing"
        )

    def test_watched_file_in_no_surface(self):
        def drop_jose(r):
            for s in r.standards:
                s.surface = [p for p in s.surface if p != "crates/decern-server/src/jose.rs"]

        self.assert_refused(drop_jose, "watched file in no surface")


class Dimensions(unittest.TestCase):
    def test_every_caller_auth_module_is_a_posture(self):
        src = standards.ROOT / "crates" / "decern-server" / "src"
        implementing = {
            str(f.relative_to(standards.ROOT))
            for f in src.glob("*.rs")
            if "impl CallerAuth for" in f.read_text()
        }
        self.assertGreaterEqual(len(implementing), 4, implementing)
        self.assertTrue(implementing <= standards.posture_files())
        self.assertIn("crates/decern-server/src/aauth.rs", standards.posture_files())

    def test_a_posture_gets_the_posture_dimensions_and_other_files_do_not(self):
        self.assertEqual(
            standards.dimensions_for(["crates/decern-server/src/aauth.rs"], []),
            standards.POSTURE_DIMENSIONS,
        )
        self.assertEqual(
            standards.dimensions_for(["crates/decern-ledger/src/merkle.rs"], []),
            standards.DEFAULT_DIMENSIONS,
        )


class Lookup(unittest.TestCase):
    def test_files_and_directory_prefixes_match(self):
        reg = standards._parse_registry(SAMPLE)
        names = lambda p: [s.name for s in standards.standards_for(reg, [p])]
        self.assertEqual(names("crates/decern-server/src/jose.rs"), ["Example (RFC 0000)"])
        self.assertEqual(
            names("crates/decern-proof/src/lib.rs"), ["Example (RFC 0000)", "Pinned thing"]
        )
        self.assertEqual(names("crates/decern-server/src/jose.rs.bak"), [])


if __name__ == "__main__":
    unittest.main()
