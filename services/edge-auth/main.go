// edge-auth is Traefik's forwardAuth check for every /v1 route that needs a
// key. It verifies the credential, the wallet's signature on this exact
// request, replays and daily rate limits, then tells Traefik who the agent is.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type auth struct {
	pub        stump.Public
	domain     cred.Domain
	issuerURL  string
	issuer     common.Address
	kv         jetstream.KeyValue
	http       *http.Client
	readLimit  int
	writeLimit int
	skew       time.Duration
	verifier   *cred.Verifier

	mu     sync.Mutex
	status map[string]cachedStatus
}

type cachedStatus struct {
	revoked bool
	at      time.Time
}

func main() {
	app := stump.New("edge-auth")
	ctx := app.Context()
	a := &auth{pub: stump.PublicFromEnv(), domain: cred.DomainFromEnv(),
		issuerURL: stump.Env("ISSUER_URL", "http://issuer:8080"),
		http:      stump.HTTPClient(5 * time.Second),
		status:    map[string]cachedStatus{}, skew: 5 * time.Minute,
		verifier: cred.VerifierFromEnv()}
	a.readLimit, _ = strconv.Atoi(stump.Env("LIMIT_READS_PER_DAY", "5000"))
	a.writeLimit, _ = strconv.Atoi(stump.Env("LIMIT_WRITES_PER_DAY", "500"))

	if err := stump.Retry(ctx, "issuer address", func() error { return a.loadIssuer(ctx) }); err != nil {
		os.Exit(1)
	}
	_, js, err := stump.NATS(ctx, "edge-auth")
	if err != nil {
		os.Exit(1)
	}
	a.kv, err = js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "edge_auth", TTL: 26 * time.Hour, Storage: jetstream.FileStorage,
		Description: "rate-limit counters and seen request signatures"})
	if err != nil {
		app.Log.Error("kv", "err", err)
		os.Exit(1)
	}
	app.Log.Info("edge-auth ready", "issuer", a.issuer.Hex())
	app.Mux.HandleFunc("/verify", a.verify)
	app.Serve()
}

func (a *auth) loadIssuer(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", a.issuerURL+"/v1/issuer", nil)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var info struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil || !common.IsHexAddress(info.Address) {
		return fmt.Errorf("issuer gave no address")
	}
	a.issuer = common.HexToAddress(info.Address)
	return nil
}

func (a *auth) deny(w http.ResponseWriter, status int, code, msg string) {
	stump.Error(w, status, code, msg)
}

func (a *auth) verify(w http.ResponseWriter, r *http.Request) {
	method := r.Header.Get("X-Forwarded-Method")
	uri := r.Header.Get("X-Forwarded-Uri")
	if method == "" || uri == "" {
		a.deny(w, 400, "bad_request", "expected a Traefik forwardAuth request")
		return
	}
	enc := r.Header.Get(cred.HeaderCredential)
	if enc == "" {
		stump.JSON(w, http.StatusPaymentRequired, a.pub.PurchaseTerms())
		return
	}
	c, err := cred.Decode(enc)
	if err != nil {
		a.deny(w, 401, "invalid_credential", err.Error())
		return
	}
	now := time.Now()
	if err := c.Verify(a.domain, a.issuer, now); err != nil {
		a.deny(w, 401, "invalid_credential", err.Error())
		return
	}
	if revoked, err := a.revoked(r.Context(), c.ID); err != nil {
		a.deny(w, 503, "issuer_unavailable", "cannot check revocation right now")
		return
	} else if revoked {
		a.deny(w, 401, "credential_revoked", "")
		return
	}
	ts, err := cred.ParseTimestamp(r.Header.Get(cred.HeaderTimestamp))
	if err != nil || now.Sub(time.Unix(ts, 0)).Abs() > a.skew {
		a.deny(w, 401, "bad_timestamp", "X-Stump-Timestamp must be unix seconds within 5 minutes")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		a.deny(w, 400, "bad_body", "")
		return
	}
	sig := r.Header.Get(cred.HeaderSignature)
	signer := common.HexToAddress(c.Subject)
	if err := a.verifier.VerifyText(r.Context(), cred.RequestPayload(method, uri, ts, body), sig, signer); err != nil {
		a.deny(w, 401, "bad_signature", "X-Stump-Signature must be the credential subject's signature of this request")
		return
	}
	// Each signature works once.
	h := sha256.Sum256([]byte(sig))
	if _, err := a.kv.Create(r.Context(), "seen."+hex.EncodeToString(h[:16]), []byte{1}); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			a.deny(w, 401, "replayed_request", "sign every request afresh")
		} else {
			a.deny(w, 503, "limits_unavailable", "")
		}
		return
	}
	kind, limit := "r", a.readLimit
	if method != "GET" && method != "HEAD" {
		kind, limit = "w", a.writeLimit
	}
	n, err := a.count(r.Context(), fmt.Sprintf("rl.%s.%s.%s", signer.Hex(), now.UTC().Format("20060102"), kind))
	if err != nil {
		a.deny(w, 503, "limits_unavailable", "")
		return
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(max(limit-n, 0)))
	if n > limit {
		a.deny(w, 429, "rate_limited", "daily limit reached; it resets at 00:00 UTC")
		return
	}
	w.Header().Set(cred.HeaderAgent, signer.Hex())
	w.Header().Set(cred.HeaderPlan, c.Plan)
	w.Header().Set(cred.HeaderCredentialID, c.ID)
	w.WriteHeader(200)
}

// count increments a counter and returns the new value.
func (a *auth) count(ctx context.Context, key string) (int, error) {
	for range 10 {
		e, err := a.kv.Get(ctx, key)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			if _, err := a.kv.Create(ctx, key, []byte("1")); err == nil {
				return 1, nil
			}
			continue
		} else if err != nil {
			return 0, err
		}
		n, _ := strconv.Atoi(string(e.Value()))
		if _, err := a.kv.Update(ctx, key, []byte(strconv.Itoa(n+1)), e.Revision()); err == nil {
			return n + 1, nil
		}
	}
	return 0, errors.New("counter busy")
}

// revoked asks issuer, caching answers for a minute.
func (a *auth) revoked(ctx context.Context, id string) (bool, error) {
	a.mu.Lock()
	s, ok := a.status[id]
	a.mu.Unlock()
	if ok && time.Since(s.at) < time.Minute {
		return s.revoked, nil
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", a.issuerURL+"/internal/credentials/"+id+"/status", nil)
	resp, err := a.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return true, nil // signed but unknown: treat as revoked
	}
	var st struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return false, err
	}
	a.mu.Lock()
	if len(a.status) > 10000 {
		a.status = map[string]cachedStatus{}
	}
	a.status[id] = cachedStatus{revoked: st.Revoked, at: time.Now()}
	a.mu.Unlock()
	return st.Revoked, nil
}
