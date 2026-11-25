// billing turns a key request into a credential. Each payment rail is a
// PaymentProvider; lab runs only the trial rail, and the others answer
// 503 payments_disabled.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/andriivladyka/thewoodenstump/pkg/ports"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type billing struct {
	db        *pgxpool.Pool
	pub       stump.Public
	issuerURL string
	rails     map[string]ports.PaymentProvider
	trial     *ports.Trial
	http      *http.Client
}

func main() {
	app := stump.New("billing")
	ctx := app.Context()
	pub := stump.PublicFromEnv()
	days, _ := strconv.Atoi(stump.Env("TRIAL_DAYS", "30"))
	trial := ports.NewTrial(pub.TrialEnabled, days, stump.Env("TRIAL_ALLOWLIST", ""))
	db, err := stump.DB(ctx, "billing")
	if err != nil {
		os.Exit(1)
	}
	if err := stump.Migrate(ctx, db,
		`CREATE TABLE IF NOT EXISTS orders (
			id text PRIMARY KEY, wallet text NOT NULL, chain_id bigint NOT NULL, rail text NOT NULL,
			terms_version text NOT NULL, agent_card_url text NOT NULL, status text NOT NULL,
			credential_id text, credential text, expires_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS orders_wallet ON orders (lower(wallet), rail, status)`,
		`CREATE TABLE IF NOT EXISTS payment_events (
			id bigserial PRIMARY KEY, rail text NOT NULL, body jsonb, received_at timestamptz NOT NULL DEFAULT now())`,
	); err != nil {
		app.Log.Error("migrate", "err", err)
		os.Exit(1)
	}
	b := &billing{db: db, pub: pub, trial: trial,
		issuerURL: stump.Env("ISSUER_URL", "http://issuer:8080"),
		http:      stump.HTTPClient(10 * time.Second),
		rails: map[string]ports.PaymentProvider{
			"trial":  trial,
			"x402":   &ports.X402{On: pub.X402Enabled},
			"stripe": &ports.Stripe{On: pub.StripeEnabled},
		}}
	app.Mux.HandleFunc("POST /v1/keys", b.buy)
	app.Mux.HandleFunc("POST /v1/payments/webhooks/{rail}", b.webhook)
	app.Serve()
}

type keyRequest struct {
	Wallet       string `json:"wallet"`
	ChainID      int64  `json:"chain_id"`
	TermsVersion string `json:"terms_version"`
	AgentCardURL string `json:"agent_card_url"`
	Rail         string `json:"rail"`
}

func (b *billing) buy(w http.ResponseWriter, r *http.Request) {
	var req keyRequest
	if err := stump.ReadJSON(r, 4096, &req); err != nil {
		stump.Error(w, 400, "bad_request", err.Error())
		return
	}
	if !common.IsHexAddress(req.Wallet) || req.ChainID <= 0 || req.AgentCardURL == "" {
		stump.Error(w, 400, "bad_request", "wallet, chain_id and agent_card_url are required")
		return
	}
	if req.TermsVersion != b.pub.TermsVersion {
		stump.JSON(w, 409, stump.Problem{Error: "terms_version_mismatch",
			Message: "accept the current terms version", Detail: map[string]string{
				"current": b.pub.TermsVersion, "terms_url": b.pub.URL + "/.well-known/terms.json"}})
		return
	}
	if req.Rail == "" {
		req.Rail = "x402"
		if b.trial.Enabled() && b.trial.Allowed(common.HexToAddress(req.Wallet)) {
			req.Rail = "trial"
		}
	}
	rail, ok := b.rails[req.Rail]
	if !ok {
		stump.Error(w, 400, "unknown_rail", "use trial, x402 or stripe")
		return
	}
	if !rail.Enabled() {
		stump.JSON(w, 503, stump.Problem{Error: "payments_disabled",
			Message: req.Rail + " payments are not switched on here", Detail: b.pub.PurchaseTerms()})
		return
	}
	wallet := common.HexToAddress(req.Wallet)

	// One live trial key per wallet: hand back the one already issued.
	if req.Rail == "trial" {
		var encoded string
		var expires time.Time
		err := b.db.QueryRow(r.Context(), `SELECT credential, expires_at FROM orders
			WHERE lower(wallet)=lower($1) AND rail='trial' AND status='issued' AND expires_at > now()
			ORDER BY created_at DESC LIMIT 1`, wallet.Hex()).Scan(&encoded, &expires)
		if err == nil {
			stump.JSON(w, 200, map[string]any{"credential": encoded, "expires_at": expires.Unix(), "reused": true})
			return
		} else if !errors.Is(err, pgx.ErrNoRows) {
			stump.Error(w, 500, "lookup_failed", err.Error())
			return
		}
	}

	id := make([]byte, 12)
	rand.Read(id)
	order := hex.EncodeToString(id)
	if _, err := b.db.Exec(r.Context(), `INSERT INTO orders (id, wallet, chain_id, rail, terms_version, agent_card_url, status)
		VALUES ($1,$2,$3,$4,$5,$6,'pending')`, order, wallet.Hex(), req.ChainID, req.Rail, req.TermsVersion, req.AgentCardURL); err != nil {
		stump.Error(w, 500, "store_failed", err.Error())
		return
	}
	p, err := rail.Start(r.Context(), ports.PurchaseRequest{OrderID: order, Wallet: wallet, ChainID: req.ChainID})
	switch {
	case errors.Is(err, ports.ErrNotEligible):
		b.db.Exec(r.Context(), `UPDATE orders SET status='refused' WHERE id=$1`, order)
		terms := b.pub.PurchaseTerms()
		terms["message"] = "This wallet is not on the trial allowlist, and paid rails are switched off here."
		stump.JSON(w, 402, terms)
		return
	case errors.Is(err, ports.ErrPaymentsDisabled):
		stump.Error(w, 503, "payments_disabled", req.Rail+" payments are not switched on here")
		return
	case err != nil:
		stump.Error(w, 502, "payment_failed", err.Error())
		return
	}
	issued, err := b.issue(r, wallet, req, p)
	if err != nil {
		b.db.Exec(r.Context(), `UPDATE orders SET status='failed' WHERE id=$1`, order)
		stump.Error(w, 502, "issue_failed", err.Error())
		return
	}
	b.db.Exec(r.Context(), `UPDATE orders SET status='issued', credential_id=$2, credential=$3, expires_at=to_timestamp($4)
		WHERE id=$1`, order, issued.Credential.ID, issued.Encoded, issued.Credential.ExpiresAt)
	stump.JSON(w, 201, map[string]any{"credential": issued.Encoded, "credential_json": issued.Credential,
		"expires_at": issued.Credential.ExpiresAt, "order": order})
}

type issued struct {
	Credential struct {
		ID        string `json:"id"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"credential"`
	Raw     json.RawMessage `json:"-"`
	Encoded string          `json:"encoded"`
}

func (b *billing) issue(r *http.Request, wallet common.Address, req keyRequest, p *ports.Purchase) (*issued, error) {
	body, _ := json.Marshal(map[string]any{"subject": wallet.Hex(), "chain_id": req.ChainID, "plan": p.Plan,
		"terms_version": req.TermsVersion, "payment_ref": p.PaymentRef, "valid_days": p.ValidDays})
	hreq, _ := http.NewRequestWithContext(r.Context(), "POST", b.issuerURL+"/internal/credentials", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("issuer answered %d", resp.StatusCode)
	}
	var out issued
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (b *billing) webhook(w http.ResponseWriter, r *http.Request) {
	rail, ok := b.rails[r.PathValue("rail")]
	if !ok || !rail.Enabled() {
		stump.Error(w, 503, "payments_disabled", "this payment rail is not switched on here")
		return
	}
	stump.Error(w, 501, "not_implemented", "webhook handling comes with the paid rails")
}
