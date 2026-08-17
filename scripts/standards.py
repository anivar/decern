#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standards registry — machine interface for agents and graph orchestration.

The registry (`.agent/standards/registry.yaml`) is the ground truth for which
external specs govern which files. This script makes that answerable without
fragile `grep -B14`, and emits shapes graph engineering can consume:

  nodes  = standards + surface paths
  edges  = implements (file → standard)
  ground = one shared brief for every parallel branch
  fan-out dimensions derived from implicated standards (fake-edge tested)

Commands:
  check              integrity gate (wired into scripts/verify.sh)
  for <path>…        JSON: standards governing those paths + grounding brief + dimensions
  graph [--paths …]  JSON: bipartite graph (optionally induced by paths)
  brief <path>…      Markdown grounding brief only (for pasting into an agent)

No third-party YAML dependency: the registry schema is a constrained subset.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / ".agent" / "standards" / "registry.yaml"

# Server modules that look standard-facing if left unlisted. Everything else under
# these globs must appear in some `surface` or in `non_surface`.
WATCHED = [
    "crates/decern-server/src/*.rs",
]

# Review dimensions suggested when a path hits a caller-posture surface. Independent
# of each other (fake-edge test): none consumes another's output.
POSTURE_DIMENSIONS = [
    "fail-open: unknown alg, header, or claim that is ignored instead of refused",
    "binding: authenticated caller can name a principal that is not theirs",
    "replay-or-confusion: captured credential or signature verifies when it should not",
]

DEFAULT_DIMENSIONS = [
    "correctness: inputs or orderings that produce a wrong result",
    "fail-open: unknown or unmapped cases that pass instead of refusing",
    "tests: assertions that cannot fail, or paths nothing asserts on",
]

POSTURE_FILES = {
    "crates/decern-server/src/sig.rs",
    "crates/decern-server/src/bearer.rs",
    "crates/decern-server/src/spiffe.rs",
    "crates/decern-server/src/caller.rs",
}


@dataclass
class Standard:
    name: str
    url: str
    surface: list[str] = field(default_factory=list)
    verified: str | None = None  # YYYY-MM-DD or "pinned"
    conformance: str = ""


@dataclass
class Registry:
    rule: str
    standards: list[Standard]
    non_surface: list[str]


def _parse_registry(text: str) -> Registry:
    """Parse the constrained registry schema. Not a general YAML parser."""
    # Strip comments that are full-line; keep inline alone.
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(line)
    text = "\n".join(lines)

    rule_m = re.search(r"^rule:\s*>-\s*\n((?:[ \t]+.+\n?)+)", text, re.M)
    rule = ""
    if rule_m:
        rule = " ".join(l.strip() for l in rule_m.group(1).splitlines() if l.strip())

    non_surface: list[str] = []
    ns_m = re.search(r"^non_surface:\s*\n((?:[ \t]+-.+\n?)+)", text, re.M)
    if ns_m:
        non_surface = re.findall(r"-\s+(\S+)", ns_m.group(1))

    standards: list[Standard] = []
    # Split on top-level list entries under standards:
    body_m = re.search(r"^standards:\s*\n([\s\S]*)", text, re.M)
    if not body_m:
        raise SystemExit("registry: missing standards: key")
    body = body_m.group(1)
    # Cut off non_surface if it appears after standards (shouldn't when ordered first)
    if "\nnon_surface:" in body:
        body = body.split("\nnon_surface:")[0]

    chunks = re.split(r"\n  - name: ", body)
    for i, chunk in enumerate(chunks):
        chunk = chunk.strip("\n")
        if not chunk.strip():
            continue
        # Split drops the delimiter; the first chunk still starts with "  - name: ".
        if i == 0:
            m = re.match(r"\s*- name:\s*", chunk)
            if not m:
                continue
            chunk = chunk[m.end() :]
        name_line, _, rest = chunk.partition("\n")
        name = name_line.strip()
        url_m = re.search(r"^\s+url:\s+(\S+)\s*$", rest, re.M)
        url = url_m.group(1) if url_m else ""
        verified_m = re.search(r"^\s+verified:\s+(\S+)\s*$", rest, re.M)
        verified = verified_m.group(1) if verified_m else None
        if verified in ("null", "~", "None"):
            verified = None

        surface: list[str] = []
        surf_m = re.search(r"^\s+surface:\s*\n((?:\s+-\s+\S+\n?)+)", rest, re.M)
        if surf_m:
            surface = re.findall(r"-\s+(\S+)", surf_m.group(1))

        conf = ""
        conf_m = re.search(r"^\s+conformance:\s*>-\s*\n((?:\s+.+\n?)+)", rest, re.M)
        if conf_m:
            conf = " ".join(
                l.strip() for l in conf_m.group(1).splitlines() if l.strip()
            )

        standards.append(
            Standard(
                name=name,
                url=url,
                surface=surface,
                verified=verified,
                conformance=conf,
            )
        )

    if not standards:
        raise SystemExit("registry: no standards parsed")
    return Registry(rule=rule, standards=standards, non_surface=non_surface)


def load() -> Registry:
    return _parse_registry(REGISTRY.read_text())


def _path_matches(surface: str, path: str) -> bool:
    """surface may be a file or a directory prefix (trailing /)."""
    path = path.replace("\\", "/")
    surface = surface.replace("\\", "/")
    if surface.endswith("/"):
        return path == surface.rstrip("/") or path.startswith(surface)
    return path == surface or path.startswith(surface.rstrip("/") + "/")


def standards_for(reg: Registry, paths: list[str]) -> list[Standard]:
    hit: list[Standard] = []
    seen: set[str] = set()
    for p in paths:
        p = p.replace("\\", "/")
        # Allow repo-relative or absolute under ROOT
        try:
            rel = str(Path(p).resolve().relative_to(ROOT))
        except Exception:
            rel = p
        for std in reg.standards:
            if std.name in seen:
                continue
            if any(_path_matches(s, rel) for s in std.surface):
                hit.append(std)
                seen.add(std.name)
    return hit


def dimensions_for(paths: list[str], stds: list[Standard]) -> list[str]:
    rels = []
    for p in paths:
        try:
            rels.append(str(Path(p).resolve().relative_to(ROOT)))
        except Exception:
            rels.append(p.replace("\\", "/"))
    if any(r in POSTURE_FILES or any(r.startswith(f[:-3]) for f in POSTURE_FILES) for r in rels):
        # posture surfaces: use the three independent auth dimensions
        dims = list(POSTURE_DIMENSIONS)
    else:
        dims = list(DEFAULT_DIMENSIONS)
    # Optional extras from conformance language — only if not already covered
    blob = " ".join(s.conformance.lower() for s in stds)
    extras = []
    if "replay" in blob and not any(d.startswith("replay") for d in dims):
        extras.append(
            "replay: a captured credential or signature verifies again inside its window"
        )
    if ("alg" in blob or "algorithm" in blob) and not any(
        "alg" in d for d in dims
    ):
        extras.append("alg-confusion: a disallowed or missing alg reaches verification")
    # Fake-edge: extras are independent of the base three; cap total width at 5
    return (dims + extras)[:5]


def grounding_brief(reg: Registry, paths: list[str], stds: list[Standard]) -> str:
    lines = [
        "# Standards grounding brief",
        "",
        "Facts only. Hand this unchanged to every parallel review branch.",
        "",
        f"Registry rule: {reg.rule}",
        "",
        "## Paths under review",
    ]
    for p in paths:
        lines.append(f"- `{p}`")
    lines.append("")
    if not stds:
        lines.append("## Standards")
        lines.append("None listed for these paths. If the change is standard-facing, that is a registry gap.")
        return "\n".join(lines)
    lines.append("## Standards")
    for s in stds:
        lines.append(f"### {s.name}")
        lines.append(f"- url: {s.url}")
        lines.append(f"- verified: {s.verified or 'MISSING'}")
        lines.append(f"- surface: {', '.join(s.surface)}")
        lines.append(f"- conformance: {s.conformance}")
        lines.append("")
    lines.append("## Required agent action")
    lines.append(
        "Before editing a listed surface, fetch and read the current text at each url. "
        "Do not work from memory. Update `verified` and the conformance note in the same change."
    )
    return "\n".join(lines)


def emit_graph(reg: Registry, paths: list[str] | None) -> dict:
    stds = reg.standards
    if paths:
        stds = standards_for(reg, paths)
        # include only surfaces that intersect paths
        path_set = set()
        for p in paths:
            try:
                path_set.add(str(Path(p).resolve().relative_to(ROOT)))
            except Exception:
                path_set.add(p)

    nodes = []
    edges = []
    for s in stds:
        sid = f"std:{s.name}"
        nodes.append(
            {
                "id": sid,
                "kind": "standard",
                "name": s.name,
                "url": s.url,
                "verified": s.verified,
            }
        )
        for surf in s.surface:
            if paths and not any(_path_matches(surf, p) for p in path_set):
                # still emit the surface node if the standard was implicated
                pass
            fid = f"file:{surf}"
            if not any(n["id"] == fid for n in nodes):
                nodes.append({"id": fid, "kind": "surface", "path": surf})
            edges.append({"from": fid, "to": sid, "rel": "implements"})
    return {
        "nodes": nodes,
        "edges": edges,
        "note": (
            "Two files that share a standard are not edit-dependent. "
            "An edge means implements, not dataflow — apply the fake-edge test before serialising work."
        ),
    }


def cmd_check(reg: Registry) -> int:
    fail = 0

    def bad(msg: str) -> None:
        nonlocal fail
        print(f"standards: {msg}", file=sys.stderr)
        fail = 1

    if not reg.rule:
        bad("missing top-level rule")

    seen_names: set[str] = set()
    all_surfaces: list[str] = []
    for s in reg.standards:
        if s.name in seen_names:
            bad(f"duplicate standard name: {s.name}")
        seen_names.add(s.name)
        if not s.url:
            bad(f"{s.name}: missing url")
        if not s.surface:
            bad(f"{s.name}: empty surface")
        if s.verified is None:
            bad(f"{s.name}: missing verified: (YYYY-MM-DD or pinned)")
        elif s.verified != "pinned":
            try:
                date.fromisoformat(s.verified)
            except ValueError:
                bad(f"{s.name}: verified: not YYYY-MM-DD or pinned ({s.verified!r})")
        for surf in s.surface:
            all_surfaces.append(surf)
            p = ROOT / surf
            if surf.endswith("/"):
                if not p.is_dir():
                    bad(f"{s.name}: surface directory missing: {surf}")
            else:
                if not p.exists():
                    bad(f"{s.name}: surface path missing: {surf}")

    for ns in reg.non_surface:
        if not (ROOT / ns).exists():
            bad(f"non_surface path missing: {ns}")

    # Reverse: watched files must be listed or explicitly non_surface
    covered: set[str] = set()
    for surf in all_surfaces:
        if surf.endswith("/"):
            for p in (ROOT / surf).rglob("*"):
                if p.is_file():
                    covered.add(str(p.relative_to(ROOT)))
        else:
            covered.add(surf)
    covered.update(reg.non_surface)

    for pattern in WATCHED:
        for p in ROOT.glob(pattern):
            rel = str(p.relative_to(ROOT))
            if rel not in covered and not any(
                rel.startswith(s) for s in all_surfaces if s.endswith("/")
            ):
                # also allow if any surface is a prefix match for a file listed as dir
                bad(
                    f"watched file in no surface and no non_surface: {rel} "
                    f"(report it, or add it to a standard / non_surface)"
                )

    if fail == 0:
        print(
            f"standards: ok ({len(reg.standards)} entries, "
            f"{len(all_surfaces)} surfaces, {len(reg.non_surface)} non_surface)"
        )
    return fail


def cmd_for(reg: Registry, paths: list[str]) -> int:
    stds = standards_for(reg, paths)
    payload = {
        "paths": paths,
        "rule": reg.rule,
        "standards": [
            {
                "name": s.name,
                "url": s.url,
                "verified": s.verified,
                "surface": s.surface,
                "conformance": s.conformance,
            }
            for s in stds
        ],
        "dimensions": dimensions_for(paths, stds),
        "grounding": grounding_brief(reg, paths, stds),
        "graph": emit_graph(reg, paths),
    }
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="integrity gate for verify.sh")
    p_for = sub.add_parser("for", help="JSON grounding payload for paths")
    p_for.add_argument("paths", nargs="+")
    p_graph = sub.add_parser("graph", help="JSON bipartite graph")
    p_graph.add_argument("--paths", nargs="*", default=None)
    p_brief = sub.add_parser("brief", help="Markdown grounding brief")
    p_brief.add_argument("paths", nargs="+")

    args = ap.parse_args()
    reg = load()

    if args.cmd == "check":
        return cmd_check(reg)
    if args.cmd == "for":
        return cmd_for(reg, args.paths)
    if args.cmd == "graph":
        json.dump(emit_graph(reg, args.paths), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.cmd == "brief":
        stds = standards_for(reg, args.paths)
        sys.stdout.write(grounding_brief(reg, args.paths, stds))
        sys.stdout.write("\n")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
