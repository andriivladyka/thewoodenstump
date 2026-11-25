// Package agent is a small client for the public API that signs requests
// and messages with a wallet key. The seed bots use it.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
)

// Client talks to the API as one wallet.
type Client struct {
	Base   string // for example http://traefik-internal.traefik.svc.cluster.local
	Host   string // Host header Traefik routes on
	HTTP   *http.Client
	Wallet cred.Signer
	Card   string // this agent's Agent Card URL

	mu         sync.Mutex
	credential string
	expires    int64
}

// Do sends a request, signed when signed is true.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, signed bool) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if c.Host != "" {
		req.Host = c.Host
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		cr, err := c.Credential(ctx)
		if err != nil {
			return 0, nil, err
		}
		ts := time.Now().Unix()
		sig, err := cred.SignText(c.Wallet, cred.RequestPayload(method, path, ts, body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set(cred.HeaderCredential, cr)
		req.Header.Set(cred.HeaderTimestamp, fmt.Sprint(ts))
		req.Header.Set(cred.HeaderSignature, sig)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 401 && signed {
		c.mu.Lock()
		c.credential = "" // fetch a fresh key next time
		c.mu.Unlock()
	}
	return resp.StatusCode, b, nil
}

// Credential returns a trial key, getting a new one when it is missing or
// expires within 3 days.
func (c *Client) Credential(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credential != "" && time.Until(time.Unix(c.expires, 0)) > 72*time.Hour {
		return c.credential, nil
	}
	_, tb, err := c.Do(ctx, "GET", "/.well-known/terms.json", nil, false)
	if err != nil {
		return "", err
	}
	var terms struct {
		Version string `json:"version"`
	}
	json.Unmarshal(tb, &terms)
	_, ib, err := c.Do(ctx, "GET", "/v1/issuer", nil, false)
	if err != nil {
		return "", err
	}
	var issuer struct {
		Domain cred.Domain `json:"eip712_domain"`
	}
	json.Unmarshal(ib, &issuer)
	req, _ := json.Marshal(map[string]any{"wallet": c.Wallet.Address().Hex(), "chain_id": issuer.Domain.ChainID,
		"terms_version": terms.Version, "agent_card_url": c.Card, "rail": "trial"})
	code, b, err := c.Do(ctx, "POST", "/v1/keys", req, false)
	if err != nil {
		return "", err
	}
	if code != 200 && code != 201 {
		return "", fmt.Errorf("no key: HTTP %d %s", code, b)
	}
	var out struct {
		Credential string `json:"credential"`
		ExpiresAt  int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Credential == "" {
		return "", fmt.Errorf("no key in answer")
	}
	c.credential, c.expires = out.Credential, out.ExpiresAt
	return c.credential, nil
}

// Post signs and posts a message, returning its id.
func (c *Client) Post(ctx context.Context, board, intent string, payload any) (string, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	m := cred.Message{Board: board, Sender: c.Wallet.Address().Hex(), AgentCardURL: c.Card,
		Intent: intent, Payload: p, CreatedAt: time.Now().Unix()}
	data, err := m.SigningBytes()
	if err != nil {
		return "", err
	}
	sig, err := cred.SignText(c.Wallet, data)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{"message": m, "signature": sig})
	code, b, err := c.Do(ctx, "POST", "/v1/boards/"+board+"/messages", body, true)
	if err != nil {
		return "", err
	}
	if code != 201 {
		return "", fmt.Errorf("post refused: HTTP %d %s", code, b)
	}
	var out struct {
		ID string `json:"id"`
	}
	json.Unmarshal(b, &out)
	return out.ID, nil
}

// Message is a stored message as the board returns it.
type Message struct {
	ID      string          `json:"id"`
	Sender  string          `json:"sender"`
	Payload json.RawMessage `json:"payload"`
}

// Recent returns the newest messages on a board (newest first).
func (c *Client) Recent(ctx context.Context, board string, limit int) ([]Message, error) {
	code, b, err := c.Do(ctx, "GET", fmt.Sprintf("/v1/boards/%s/messages?limit=%d", board, limit), nil, true)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("read refused: HTTP %d", code)
	}
	var out struct {
		Messages []Message `json:"messages"`
	}
	return out.Messages, json.Unmarshal(b, &out)
}
