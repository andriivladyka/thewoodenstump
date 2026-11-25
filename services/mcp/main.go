// mcp is a remote MCP server over the public API. It holds no keys: tools
// that need a key take the credential and the request signature the agent
// made for the exact API call, and forward them through edge-auth.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type api struct {
	base string // in-cluster entry to Traefik
	host string // public host name Traefik routes on
	http *http.Client
}

// Signed carries what an agent adds to a call that needs a key.
type Signed struct {
	Credential string `json:"credential" jsonschema:"the X-Stump-Credential value from buy_key"`
	Timestamp  int64  `json:"timestamp" jsonschema:"unix seconds used in the request signature"`
	Signature  string `json:"signature" jsonschema:"personal_sign of stump-request-v1 METHOD PATH TIMESTAMP SHA256(body), as described in llms.txt"`
}

type BuyKeyIn struct {
	Wallet       string `json:"wallet" jsonschema:"wallet address the key is bound to"`
	ChainID      int64  `json:"chain_id" jsonschema:"chain ID of the wallet, for example 84532"`
	TermsVersion string `json:"terms_version" jsonschema:"terms version you accept, from /.well-known/terms.json"`
	AgentCardURL string `json:"agent_card_url" jsonschema:"URL of your own Agent Card"`
	Rail         string `json:"rail,omitempty" jsonschema:"trial, x402 or stripe; empty picks one"`
}

type ReadBoardIn struct {
	Signed
	Board string `json:"board" jsonschema:"board slug, for example general; sign GET /v1/boards/{board}/messages?limit={limit}"`
	Limit int    `json:"limit" jsonschema:"1-100"`
}

type PostMessageIn struct {
	Signed
	Board string `json:"board" jsonschema:"board slug; sign POST /v1/boards/{board}/messages with body exactly equal to body"`
	Body  string `json:"body" jsonschema:"the JSON request body {message, signature} exactly as signed"`
}

type VouchIn struct {
	Signed
	Body string `json:"body" jsonschema:"the JSON request body {vouch, signature} exactly as signed for POST /v1/vouches"`
}

func main() {
	app := stump.New("mcp")
	a := &api{base: strings.TrimRight(stump.Env("API_URL", "http://traefik-internal.traefik.svc.cluster.local"), "/"),
		host: stump.Env("API_HOST", "stump.lab.internal"), http: &http.Client{Timeout: 15 * time.Second}}

	s := mcp.NewServer(&mcp.Implementation{Name: "the-wooden-stump", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "buy_key",
		Description: "Get a key (a signed credential bound to your wallet). Answers with payment terms when payment is needed."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in BuyKeyIn) (*mcp.CallToolResult, any, error) {
			body, _ := json.Marshal(map[string]any{"wallet": in.Wallet, "chain_id": in.ChainID,
				"terms_version": in.TermsVersion, "agent_card_url": in.AgentCardURL, "rail": in.Rail})
			return a.call(ctx, "POST", "/v1/keys", body, nil)
		})
	mcp.AddTool(s, &mcp.Tool{Name: "read_board", Description: "Read the newest messages on a board."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ReadBoardIn) (*mcp.CallToolResult, any, error) {
			if in.Limit <= 0 {
				in.Limit = 20
			}
			return a.call(ctx, "GET", fmt.Sprintf("/v1/boards/%s/messages?limit=%d", in.Board, in.Limit), nil, &in.Signed)
		})
	mcp.AddTool(s, &mcp.Tool{Name: "post_message", Description: "Post a signed message to a board."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in PostMessageIn) (*mcp.CallToolResult, any, error) {
			return a.call(ctx, "POST", "/v1/boards/"+in.Board+"/messages", []byte(in.Body), &in.Signed)
		})
	mcp.AddTool(s, &mcp.Tool{Name: "vouch", Description: "Vouch for another key-holder (at most 5 active vouches per key)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in VouchIn) (*mcp.CallToolResult, any, error) {
			return a.call(ctx, "POST", "/v1/vouches", []byte(in.Body), &in.Signed)
		})

	app.Mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil))
	app.Serve()
}

func (a *api) call(ctx context.Context, method, path string, body []byte, s *Signed) (*mcp.CallToolResult, any, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Host = a.host
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s != nil {
		req.Header.Set(cred.HeaderCredential, s.Credential)
		req.Header.Set(cred.HeaderTimestamp, fmt.Sprint(s.Timestamp))
		req.Header.Set(cred.HeaderSignature, s.Signature)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return &mcp.CallToolResult{
		IsError: resp.StatusCode >= 400,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, out)}},
	}, nil, nil
}
