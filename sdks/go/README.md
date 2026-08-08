<!-- SPDX-License-Identifier: Apache-2.0 -->
# decern — Go client

[![License](https://anivar.net/badge?label=license&value=Apache-2.0)](https://github.com/anivar/decern/blob/main/LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21848620.svg)](https://doi.org/10.5281/zenodo.21848620)

[Website](https://decern.anivar.net/) · [Repository](https://github.com/anivar/decern) ·
[Commands](https://github.com/anivar/decern/blob/main/docs/CLI.md) ·
[Issues](https://github.com/anivar/decern/issues)

Ask whether an action is allowed, and get an answer somebody can check afterwards.
Standard library only — no dependencies.

```sh
go get github.com/anivar/decern/sdks/go
# and a server to ask:
cargo install decern-server && decern-serve --trust-proxy
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anivar/decern/sdks/go"
)

func main() {
	c := decern.NewClient(&decern.ClientOptions{BaseURL: "http://127.0.0.1:8080"})

	d, err := c.Evaluate(context.Background(), decern.EvaluateArgs{
		Subject:  decern.Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: decern.Entity{"type": "Resource", "id": "claim1"},
	})
	if err != nil {
		log.Fatalf("evaluation failed: %v", err)
	}
	fmt.Println(d.Allowed, d.Reasons)
}
```

Also on the client: `Pubkey` (the Ed25519 key id the log is signed with) and `Healthy`.
`Context` is advisory — the server overrides anything it derives itself (the clock, the
accountable owner), so a caller cannot talk its way into a decision by supplying them.

## What the server gives you

[decern](https://github.com/anivar/decern) is an [AuthZEN
1.0](https://openid.net/specs/authorization-api-1_0.html) authorization server whose safety
rules are machine-checked over every input, and whose decisions land in an append-only,
signed, hash-chained log **before** they are served — a decision that cannot be recorded is
refused, and a third party can verify what was decided without trusting the operator:

```sh
decern verify --ledger <file> --pubkey <key>   # the chain and every signature
decern explain --ledger <file> --seq 12        # one decision, in full
```

Obtain the public key out of band; a key handed over by the party being audited
establishes nothing.

## Test

```sh
cd sdks/go && go test ./...
```

Apache-2.0.
