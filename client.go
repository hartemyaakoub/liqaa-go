// Package liqaa provides a server-side Go client for the LIQAA Public API.
//
// Authenticates with sk_live_... — never expose the secret key to clients.
//
// See https://liqaa.io/docs for the full API reference.
package liqaa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://liqaa.io/api/public/v1"
	userAgent      = "liqaa-go/1.0.0"
)

// Client is a thread-safe LIQAA API client.
type Client struct {
	publicKey string
	secretKey string
	baseURL   string
	http      *http.Client
}

// New constructs a new client.
func New(publicKey, secretKey string) *Client {
	return &Client{
		publicKey: publicKey,
		secretKey: secretKey,
		baseURL:   defaultBaseURL,
		http:      &http.Client{Timeout: 8 * time.Second},
	}
}

// WithBaseURL overrides the API base URL (useful for sandbox / self-hosted).
func (c *Client) WithBaseURL(u string) *Client { c.baseURL = strings.TrimRight(u, "/"); return c }

// WithHTTPClient injects a custom *http.Client (e.g. for tracing or retries).
func (c *Client) WithHTTPClient(h *http.Client) *Client { c.http = h; return c }

// Identity is the user identity to sign for an SDK token.
type Identity struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// SDKTokenResponse is returned by ExchangeSDKToken.
type SDKTokenResponse struct {
	SDKToken  string    `json:"sdk_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ExchangeSDKToken signs an identity with sk_ and exchanges for a 1-hour browser-safe JWT.
func (c *Client) ExchangeSDKToken(ctx context.Context, id Identity) (*SDKTokenResponse, error) {
	body := struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
		Ts    int64  `json:"ts"`
	}{id.Email, id.Name, time.Now().Unix()}
	raw, _ := json.Marshal(body)
	identityB64 := base64.StdEncoding.EncodeToString(raw)

	mac := hmac.New(sha256.New, []byte(c.secretKey))
	mac.Write([]byte(identityB64))
	signature := hex.EncodeToString(mac.Sum(nil))

	req := map[string]string{
		"public_key":      c.publicKey,
		"identity_base64": identityB64,
		"signature":       signature,
	}
	out := &SDKTokenResponse{}
	if err := c.do(ctx, http.MethodPost, "/sdk-token", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ConversationCreate is the request body for CreateConversation.
type ConversationCreate struct {
	CallerEmail            string `json:"caller_email"`
	CallerName             string `json:"caller_name,omitempty"`
	CalleeEmail            string `json:"callee_email,omitempty"`
	CalleeName             string `json:"callee_name,omitempty"`
	ExternalConversationID string `json:"external_conversation_id,omitempty"`
	Title                  string `json:"title,omitempty"`
}

// Conversation is the response of CreateConversation / GetConversation.
type Conversation struct {
	OK             bool      `json:"ok"`
	Reused         bool      `json:"reused"`
	RoomName       string    `json:"room_name"`
	JoinURL        string    `json:"join_url"`
	GuestJoinURL   string    `json:"guest_join_url"`
	CallerJoinURL  string    `json:"caller_join_url"`
	CalleeJoinURL  string    `json:"callee_join_url,omitempty"`
	EmbedURL       string    `json:"embed_url"`
	ExpiresAt      time.Time `json:"expires_at"`
	MeetingID      int64     `json:"meeting_id"`
}

// CreateConversation creates or reuses a persistent room.
func (c *Client) CreateConversation(ctx context.Context, in ConversationCreate) (*Conversation, error) {
	out := &Conversation{}
	if err := c.do(ctx, http.MethodPost, "/conversations", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetConversation fetches the current state of a room.
func (c *Client) GetConversation(ctx context.Context, id string) (*Conversation, error) {
	out := &Conversation{}
	if err := c.do(ctx, http.MethodGet, "/conversations/"+id, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// EndConversation ends an active call.
func (c *Client) EndConversation(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/conversations/"+id, nil, nil)
}

// ── HTTP plumbing ─────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("liqaa request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("liqaa API error %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ErrInvalidSignature is returned by WebhookVerifier.Verify on bad signatures.
var ErrInvalidSignature = errors.New("liqaa: invalid webhook signature")
