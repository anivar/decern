// SPDX-License-Identifier: Apache-2.0
// Tests for the Go AuthZEN 1.0 Access Evaluation client.

package decern

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientEvaluate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/access/v1/evaluation" {
			t.Errorf("expected POST /access/v1/evaluation, got %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var reqBody map[string]any
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check action format
		action, ok := reqBody["action"].(map[string]any)
		if !ok || action["name"] != "Read" {
			t.Errorf("expected action to be {name: 'Read'}, got %v", reqBody["action"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"decision": true,
			"context": {
				"reasons": ["policy1"],
				"errors": []
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(&ClientOptions{
		BaseURL: server.URL,
	})

	decision, err := client.Evaluate(context.Background(), EvaluateArgs{
		Subject:  Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: Entity{"type": "Resource", "id": "claim1"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("expected decision to be true, got false")
	}

	if len(decision.Reasons) != 1 || decision.Reasons[0] != "policy1" {
		t.Errorf("expected reasons ['policy1'], got %v", decision.Reasons)
	}
}

func TestClientPubkey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/pubkey" {
			t.Errorf("expected GET /pubkey, got %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"kid": "test-kid"}`))
	}))
	defer server.Close()

	client := NewClient(&ClientOptions{
		BaseURL: server.URL,
	})

	kid, err := client.Pubkey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if kid != "test-kid" {
		t.Errorf("expected kid 'test-kid', got %v", kid)
	}
}

func TestClientHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			t.Errorf("expected GET /healthz, got %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	}))
	defer server.Close()

	client := NewClient(&ClientOptions{
		BaseURL: server.URL,
	})

	if !client.Healthy(context.Background()) {
		t.Errorf("expected healthy to be true")
	}
}

func TestClientHTTPErrorWithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"access_denied"}`))
	}))
	defer server.Close()

	client := NewClient(&ClientOptions{
		BaseURL: server.URL,
	})

	_, err := client.Evaluate(context.Background(), EvaluateArgs{
		Subject:  Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: Entity{"type": "Resource", "id": "claim1"},
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	decErr, ok := err.(*DecernError)
	if !ok {
		t.Fatalf("expected *DecernError, got %T", err)
	}

	if decErr.StatusCode != 403 {
		t.Errorf("expected StatusCode 403, got %d", decErr.StatusCode)
	}

	if decErr.Body != `{"error":"access_denied"}` {
		t.Errorf("expected Body `{\"error\":\"access_denied\"}`, got %q", decErr.Body)
	}

	if !strings.Contains(decErr.Error(), `403 Forbidden: {"error":"access_denied"}`) {
		t.Errorf("expected error message to contain body, got %q", decErr.Error())
	}
}

func TestClientHTTPErrorBodyTruncation(t *testing.T) {
	longBody := strings.Repeat("x", 600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(longBody))
	}))
	defer server.Close()

	client := NewClient(&ClientOptions{
		BaseURL: server.URL,
	})

	_, err := client.Evaluate(context.Background(), EvaluateArgs{
		Subject:  Entity{"type": "Principal", "id": "corp"},
		Action:   "Read",
		Resource: Entity{"type": "Resource", "id": "claim1"},
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	decErr, ok := err.(*DecernError)
	if !ok {
		t.Fatalf("expected *DecernError, got %T", err)
	}

	if decErr.Body != longBody {
		t.Errorf("expected Body len %d, got len %d", len(longBody), len(decErr.Body))
	}

	if !strings.HasSuffix(decErr.Error(), "...") {
		t.Errorf("expected error message to end with '...', got %q", decErr.Error())
	}
}
