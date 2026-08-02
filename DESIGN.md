<!-- SPDX-License-Identifier: Apache-2.0 -->
# decern — design

The visual identity for decern. Small, precise, and honest — like the kernel.

## The mark

<p align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/decern-mark-dark.svg">
    <img src="docs/img/decern-mark.svg" alt="decern mark" width="88" height="88">
  </picture>
</p>

The mark is **⊢** — the turnstile, logic's *“proves” / “entails”* symbol — with its
arm drawn as three segments. It says what decern does in one glyph: a decision is
**proven**, then **recorded** to an append-only, segmented ledger. The vertical bar
is the premise; the three segments are the ledger the decision lands in.

- Assets: [`docs/img/decern-mark.svg`](docs/img/decern-mark.svg) (light) ·
  [`docs/img/decern-mark-dark.svg`](docs/img/decern-mark-dark.svg) (dark).
- Single flat colour, no gradient, no shadow, no bevel.

## Wordmark

Lowercase **`decern`**, set in a **monospace** face — exact, even, deterministic,
the same character a decision is: a pure function of its inputs. Pair the mark to
the left of the wordmark (horizontal lockup) or above it (stacked).

## Colour

One accent — a deep spruce green, reading *verified / allow* — on cool graphite
neutrals. Everything else is ink and paper.

| Token | Light | Dark | Use |
|---|---|---|---|
| Accent (Spruce) | `#0E7C6B` | `#34C6AB` | the mark, links, emphasis |
| Ink | `#0C0F0E` | `#EAF0ED` | text |
| Paper | `#F5F7F6` | `#0C0F0E` | ground |
| Slate | `#5E6B67` | `#8EA09A` | muted / secondary |

Semantic colours (good / warn / bad) are separate from the accent and used only
for state, never as brand colour.

## Typography

- **Monospace** — the wordmark, code, CLI, and any exact/tabular value.
  Stack: `ui-monospace, "SF Mono", "IBM Plex Mono", Menlo, Consolas, monospace`.
- **Sans** — prose and UI.
  Stack: `-apple-system, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`.

No external font files: keep the shipped artifacts zero-egress; the system stacks
above fall back cleanly.

## Usage

- **Clearspace**: keep free space equal to the height of the mark's arm on every side.
- **Minimum size**: 16 px. Below that the three segments read as one bar — that's fine.
- **Don't**: recolour outside the palette, stretch or rotate the mark, add effects,
  or set the wordmark in a non-monospace face.
