// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/anivar/decern/sdks/go"
)

func main() {
	client := decern.NewClient(&decern.ClientOptions{
		BaseURL: "http://127.0.0.1:8080",
	})

	if !client.Healthy(context.Background()) {
		log.Fatal("Server is offline!")
	}

	fmt.Println("✅ Successfully connected to Decern server at http://127.0.0.1:8080")
	fmt.Println("Fetching public key...")

	pubkey, err := client.Pubkey(context.Background())
	if err != nil {
		log.Fatalf("Failed to fetch pubkey: %v", err)
	}
	fmt.Printf("🔐 Server Public Key: %s\n\n", pubkey)

	fmt.Println("Asking server for permission to 'Read' 'claim1'...")
	decision, err := client.Evaluate(context.Background(), decern.EvaluateArgs{
		Subject:  decern.Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: decern.Entity{"type": "Resource", "id": "claim1"},
	})
	if err != nil {
		log.Fatalf("Evaluation failed: %v", err)
	}

	if decision.Allowed {
		fmt.Println("✅ ACCESS GRANTED!")
	} else {
		fmt.Printf("❌ ACCESS DENIED! Reasons: %v\n", decision.Reasons)
	}
}
