<!-- SPDX-License-Identifier: Apache-2.0 -->
# decern Go SDK

A minimal, dependency-free Go client for the `decern` PDP speaking AuthZEN 1.0.

## Installation

```bash
go get github.com/anivar/decern/sdks/go
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anivar/decern/sdks/go"
)

func main() {
	// Defaults to http://127.0.0.1:8080 and a 5s timeout
	client := decern.NewClient(&decern.ClientOptions{
		BaseURL: "http://127.0.0.1:8080",
	})

	if !client.Healthy(context.Background()) {
		log.Fatal("decern server is not healthy")
	}

	decision, err := client.Evaluate(context.Background(), decern.EvaluateArgs{
		Subject:  decern.Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: decern.Entity{"type": "Resource", "id": "claim1"},
	})
	if err != nil {
		log.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		fmt.Println("Access granted!")
	} else {
		fmt.Printf("Access denied. Reasons: %v\n", decision.Reasons)
	}
}
```
