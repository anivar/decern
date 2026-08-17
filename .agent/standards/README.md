<!-- SPDX-License-Identifier: Apache-2.0 -->
# standards

`registry.yaml` lists every external spec decern implements. Each entry carries the spec's
url, the files that implement it (`surface`), what conformance means here, and when the text
was last read.

Start from the file you are about to change:

```
grep -B14 'src/spiffe.rs' registry.yaml
```

That names the spec governing it. Then fetch the url and read the current text — specs move,
and working from memory is how a surface drifts out of conformance without any test noticing.
Build to what it says now, add or update a test that pins the behaviour, and update the
entry's conformance note and its date in the same change.

A file that is standard-facing and appears in no `surface` list is worth reporting: it means
something is being maintained from memory.
