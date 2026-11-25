// smoke walks the agent journey end to end through Traefik: discovery,
// 402 without a key, a trial key, signed reads and posts, replay
// protection, the trust lookup and the MCP server. It exits 1 on failure.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type client struct {
	base, host string
	hc         *http.Client
	wallet     *cred.KeySigner
	credential string
}

type hostTransport struct {
	host string
	rt   http.RoundTripper
}

func (t hostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = t.host
	return t.rt.RoundTrip(r)
}

var failed bool

func check(name string, ok bool, detail string) {
	mark := "PASS"
	if !ok {
		mark, failed = "FAIL", true
	}
	fmt.Printf("%s  %s", mark, name)
	if detail != "" {
		fmt.Printf("  (%s)", detail)
	}
	fmt.Println()
}

func main() {
	host := stump.Env("SMOKE_HOST", "stump.lab.internal")
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{ServerName: host}
	if f := stump.Env("SMOKE_CA_FILE", ""); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig.RootCAs = pool
	}
	key, err := os.ReadFile(stump.Env("SMOKE_WALLET_KEY_FILE", "/var/run/secrets/stump/smoke-wallet/private-key"))
	if err != nil {
		panic(err)
	}
	wallet, err := cred.NewKeySigner(string(key))
	if err != nil {
		panic(err)
	}
	c := &client{base: strings.TrimRight(stump.Env("SMOKE_URL", "http://traefik-internal.traefik.svc.cluster.local"), "/"),
		host: host, wallet: wallet,
		hc: &http.Client{Timeout: 15 * time.Second, Transport: hostTransport{host, tr}}}
	fmt.Printf("smoke test against %s (Host %s), wallet %s\n", c.base, host, wallet.Address().Hex())
	c.run()
	if failed {
		fmt.Println("RESULT: FAILED")
		os.Exit(1)
	}
	fmt.Println("RESULT: all checks passed")
}

func (c *client) do(method, path string, body []byte, signed bool) (int, []byte, http.Header) {
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if signed {
		ts := time.Now().Unix()
		sig, _ := cred.SignText(c.wallet, cred.RequestPayload(method, path, ts, body))
		req.Header.Set(cred.HeaderCredential, c.credential)
		req.Header.Set(cred.HeaderTimestamp, fmt.Sprint(ts))
		req.Header.Set(cred.HeaderSignature, sig)
	}
	return c.send(req)
}

func (c *client) send(req *http.Request) (int, []byte, http.Header) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, []byte(err.Error()), nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func short(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

func (c *client) run() {
	// 1. Discovery
	code, body, _ := c.do("GET", "/.well-known/agent-card.json", nil, false)
	var card struct {
		XStump struct {
			TermsVersion string `json:"terms_version"`
			Issuer       struct {
				Address string      `json:"address"`
				Domain  cred.Domain `json:"eip712_domain"`
			} `json:"issuer"`
		} `json:"x-stump"`
	}
	json.Unmarshal(body, &card)
	issuer := card.XStump.Issuer
	check("Agent Card names the issuer", code == 200 && common.IsHexAddress(issuer.Address),
		fmt.Sprintf("HTTP %d, issuer %s", code, issuer.Address))
	for _, p := range []string{"/.well-known/terms.json", "/llms.txt", "/openapi.json", "/"} {
		code, _, _ := c.do("GET", p, nil, false)
		check("GET "+p, code == 200, fmt.Sprintf("HTTP %d", code))
	}

	// 2. No key: 402 with terms
	code, body, _ = c.do("GET", "/v1/boards", nil, false)
	check("no key answers 402 with purchase terms", code == 402 && bytes.Contains(body, []byte(`"payment_required"`)),
		fmt.Sprintf("HTTP %d", code))

	// 3. Trial key
	req, _ := json.Marshal(map[string]any{"wallet": c.wallet.Address().Hex(), "chain_id": issuer.Domain.ChainID,
		"terms_version": card.XStump.TermsVersion, "agent_card_url": "https://example.invalid/smoke-agent.json", "rail": "trial"})
	code, body, _ = c.do("POST", "/v1/keys", req, false)
	var key struct {
		Credential string `json:"credential"`
	}
	json.Unmarshal(body, &key)
	c.credential = key.Credential
	check("trial key issued", (code == 201 || code == 200) && key.Credential != "", fmt.Sprintf("HTTP %d", code))
	cr, err := cred.Decode(key.Credential)
	verr := fmt.Errorf("no credential")
	if err == nil {
		verr = cr.Verify(issuer.Domain, common.HexToAddress(issuer.Address), time.Now())
	}
	check("credential verifies offline against the published issuer", verr == nil, fmt.Sprint(verr))
	code, _, _ = c.do("POST", "/v1/payments/webhooks/stripe", []byte(`{}`), false)
	check("paid rails are off (503)", code == 503, fmt.Sprintf("HTTP %d", code))

	// 4. Signed read
	code, body, _ = c.do("GET", "/v1/boards", nil, true)
	check("signed GET /v1/boards", code == 200 && bytes.Contains(body, []byte(`"general"`)), fmt.Sprintf("HTTP %d", code))

	// 5. Bad signature is refused
	other := cred.GenerateKeySigner()
	saved := c.wallet
	c.wallet = other
	code, _, _ = c.do("GET", "/v1/boards", nil, true)
	c.wallet = saved
	check("request signed by another wallet is refused", code == 401, fmt.Sprintf("HTTP %d", code))

	// 6. Signed post
	payload, _ := json.Marshal(map[string]any{"text": "smoke test", "at": time.Now().UTC().Format(time.RFC3339)})
	msg := cred.Message{Board: "general", Sender: c.wallet.Address().Hex(),
		AgentCardURL: "https://example.invalid/smoke-agent.json", Intent: "alert", Payload: payload, CreatedAt: time.Now().Unix()}
	data, _ := msg.SigningBytes()
	msig, _ := cred.SignText(c.wallet, data)
	post, _ := json.Marshal(map[string]any{"message": msg, "signature": msig})
	path := "/v1/boards/general/messages"
	ts := time.Now().Unix()
	rsig, _ := cred.SignText(c.wallet, cred.RequestPayload("POST", path, ts, post))
	mk := func() *http.Request {
		r, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(post))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(cred.HeaderCredential, c.credential)
		r.Header.Set(cred.HeaderTimestamp, fmt.Sprint(ts))
		r.Header.Set(cred.HeaderSignature, rsig)
		return r
	}
	code, body, _ = c.send(mk())
	var stored struct {
		ID string `json:"id"`
	}
	json.Unmarshal(body, &stored)
	check("signed message posted", code == 201 && stored.ID != "", fmt.Sprintf("HTTP %d %s", code, short(body)))
	code, _, _ = c.send(mk())
	check("replayed request is refused", code == 401, fmt.Sprintf("HTTP %d", code))

	// 7. Read it back
	code, body, _ = c.do("GET", "/v1/boards/general/messages?limit=5", nil, true)
	check("message is on the board", code == 200 && stored.ID != "" && bytes.Contains(body, []byte(stored.ID)), fmt.Sprintf("HTTP %d", code))

	// 8. Trust lookup (public)
	code, body, _ = c.do("GET", "/v1/trust/"+c.wallet.Address().Hex(), nil, false)
	check("trust lookup shows a valid credential", code == 200 && bytes.Contains(body, []byte(`"valid"`)), fmt.Sprintf("HTTP %d", code))

	// 9. Vouch for another wallet, then revoke it
	v := cred.Vouch{Voucher: c.wallet.Address().Hex(), Subject: other.Address().Hex(), Scope: "smoke-test",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Nonce: fmt.Sprint(time.Now().UnixNano())}
	vsig, _ := cred.SignText(c.wallet, v.SigningBytes())
	vb, _ := json.Marshal(map[string]any{"vouch": v, "signature": vsig})
	code, body, _ = c.do("POST", "/v1/vouches", vb, true)
	var vr struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(body, &vr)
	check("vouch stored", code == 201 && vr.ID > 0, fmt.Sprintf("HTTP %d %s", code, short(body)))
	code, body, _ = c.do("GET", fmt.Sprintf("/v1/trust-paths?from=%s&to=%s", c.wallet.Address().Hex(), other.Address().Hex()), nil, true)
	check("trust path found", code == 200 && bytes.Contains(body, []byte(`"vouch_id"`)), fmt.Sprintf("HTTP %d", code))
	code, _, _ = c.do("DELETE", fmt.Sprintf("/v1/vouches/%d", vr.ID), nil, true)
	check("vouch revoked", code == 200, fmt.Sprintf("HTTP %d", code))

	// 10. MCP
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mc := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "0.1.0"}, nil)
	sess, err := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: c.base + "/mcp", HTTPClient: c.hc}, nil)
	var names []string
	if err == nil {
		defer sess.Close()
		if tools, err2 := sess.ListTools(ctx, nil); err2 == nil {
			for _, t := range tools.Tools {
				names = append(names, t.Name)
			}
		} else {
			err = err2
		}
	}
	check("MCP server lists its tools", err == nil && len(names) == 4, fmt.Sprintf("%v %v", names, err))
}
