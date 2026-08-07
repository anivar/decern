// SPDX-License-Identifier: Apache-2.0
// AuthZEN 1.0 Access Evaluation client for the decern PDP.

package decern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Entity represents an AuthZEN entity, e.g. {"type": "Principal", "id": "corp"}
type Entity map[string]any

// Decision is the parsed outcome of an evaluation.
type Decision struct {
	Allowed bool           `json:"allowed"`
	Reasons []string       `json:"reasons"`
	Errors  []string       `json:"errors"`
	Context map[string]any `json:"context,omitempty"`
}

// EvaluateArgs are the arguments to Evaluate.
type EvaluateArgs struct {
	Subject  Entity
	Action   any // string is normalized to {"name": s} before the request
	Resource Entity
	Context  map[string]any
}

// ClientOptions allows overriding defaults when creating a Client.
type ClientOptions struct {
	BaseURL    string
	Timeout    time.Duration
	HTTPClient *http.Client
}

// Client for a decern PDP speaking AuthZEN 1.0 Access Evaluation.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// DecernError represents a transport failure or non-2xx response from the PDP.
type DecernError struct {
	Message    string
	StatusCode int
	Body       string
}

func (e *DecernError) Error() string {
	return e.Message
}

// NewClient creates a new Client with the given options.
func NewClient(opts *ClientOptions) *Client {
	baseURL := "http://127.0.0.1:8080"
	var httpClient *http.Client

	if opts != nil {
		if opts.BaseURL != "" {
			baseURL = opts.BaseURL
		}
		if opts.HTTPClient != nil {
			httpClient = opts.HTTPClient
		} else if opts.Timeout != 0 {
			httpClient = &http.Client{Timeout: opts.Timeout}
		}
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

func (c *Client) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, buildHTTPError(method, path, resp.StatusCode, respBody)
	}

	return respBody, nil
}

func buildHTTPError(method, path string, statusCode int, respBody []byte) *DecernError {
	rawBody := string(respBody)
	bodyStr := strings.TrimSpace(rawBody)
	msg := fmt.Sprintf("%s %s -> %d %s", method, path, statusCode, http.StatusText(statusCode))
	if bodyStr != "" {
		trunc := bodyStr
		if len(bodyStr) > 512 {
			runes := []rune(bodyStr)
			if len(runes) > 512 {
				trunc = string(runes[:512]) + "..."
			}
		}
		msg = fmt.Sprintf("%s %s -> %d %s: %s", method, path, statusCode, http.StatusText(statusCode), trunc)
	}
	return &DecernError{
		Message:    msg,
		StatusCode: statusCode,
		Body:       rawBody,
	}
}

// Evaluate performs an AuthZEN access evaluation.
func (c *Client) Evaluate(ctx context.Context, args EvaluateArgs) (*Decision, error) {
	act := args.Action
	if s, ok := args.Action.(string); ok {
		act = map[string]any{"name": s}
	}

	reqBody := map[string]any{
		"subject":  args.Subject,
		"action":   act,
		"resource": args.Resource,
	}
	if args.Context != nil {
		reqBody["context"] = args.Context
	}

	raw, err := c.request(ctx, http.MethodPost, "/access/v1/evaluation", reqBody)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Decision bool           `json:"decision"`
		Context  map[string]any `json:"context"`
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse evaluation response: %w", err)
	}

	reasons := []string{}
	errors := []string{}

	if resp.Context != nil {
		if r, ok := resp.Context["reasons"].([]any); ok {
			for _, v := range r {
				if str, ok := v.(string); ok {
					reasons = append(reasons, str)
				}
			}
		}
		if e, ok := resp.Context["errors"].([]any); ok {
			for _, v := range e {
				if str, ok := v.(string); ok {
					errors = append(errors, str)
				}
			}
		}
	}

	return &Decision{
		Allowed: resp.Decision,
		Reasons: reasons,
		Errors:  errors,
		Context: resp.Context,
	}, nil
}

// Pubkey retrieves the public key used by the PDP.
func (c *Client) Pubkey(ctx context.Context) (string, error) {
	raw, err := c.request(ctx, http.MethodGet, "/pubkey", nil)
	if err != nil {
		return "", err
	}

	var resp struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("failed to parse pubkey response: %w", err)
	}

	return resp.Kid, nil
}

// Healthy returns true if the PDP is reachable and returns 'ok'.
func (c *Client) Healthy(ctx context.Context) bool {
	raw, err := c.request(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "ok"
}
