<!-- SPDX-License-Identifier: Apache-2.0 -->
# standards

`registry.yaml` lists every external spec decern touches. Per entry, the loop is:

1. **watch** — track the spec at its url for new versions.
2. **read-latest-spec** — before changing its surface, fetch and read the *current* text.
3. **conform** — build to what the spec says now, not to memory.
4. **test** — add or update a test that pins the conformant behavior.
