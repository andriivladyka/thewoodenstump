// issuer signs credentials (only billing may ask), records revocations and
// answers public trust lookups. It emits credential events to NATS.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type issuer struct {
	db     *pgxpool.Pool
	js     jetstream.JetStream
	signer cred.Signer
	domain cred.Domain
}

func main() {
	app := stump.New("issuer")
	ctx := app.Context()
	key, err := os.ReadFile(stump.Env("ISSUER_KEY_FILE", "/var/run/secrets/stump/issuer-key/private-key"))
	if err != nil {
		app.Log.Error("cannot read issuer key", "err", err)
		os.Exit(2)
	}
	signer, err := cred.NewKeySigner(string(key))
	if err != nil {
		app.Log.Error("bad issuer key", "err", err)
		os.Exit(2)
	}
	db, err := stump.DB(ctx, "issuer")
	if err != nil {
		os.Exit(1)
	}
	if err := stump.Migrate(ctx, db,
		`CREATE TABLE IF NOT EXISTS credentials (
			id text PRIMARY KEY, subject text NOT NULL, subject_chain_id bigint NOT NULL,
			plan text NOT NULL, terms_version text NOT NULL, payment_ref text NOT NULL,
			issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
			signature text NOT NULL, revoked_at timestamptz, revoke_reason text)`,
		`CREATE INDEX IF NOT EXISTS credentials_subject ON credentials (lower(subject))`,
		// Wallets the operator blocked for abuse: their keys are revoked and
		// no new ones are issued.
		`CREATE TABLE IF NOT EXISTS blocked_wallets (
			wallet text PRIMARY KEY, reason text NOT NULL, blocked_at timestamptz NOT NULL DEFAULT now())`,
	); err != nil {
		app.Log.Error("migrate", "err", err)
		os.Exit(1)
	}
	_, js, err := stump.NATS(ctx, "issuer")
	if err != nil {
		os.Exit(1)
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: "CREDENTIALS", Subjects: []string{"stump.issuer.>"}, Storage: jetstream.FileStorage,
	}); err != nil {
		app.Log.Error("stream", "err", err)
		os.Exit(1)
	}
	is := &issuer{db: db, js: js, signer: signer, domain: cred.DomainFromEnv()}
	app.Gauges(is.gauges)
	app.Log.Info("issuer ready", "address", signer.Address().Hex(), "domain", is.domain.Name)

	app.Mux.HandleFunc("GET /v1/issuer", is.info)
	app.Mux.HandleFunc("GET /v1/trust/{wallet}", is.lookup)
	app.Mux.HandleFunc("POST /internal/credentials", is.issue)
	app.Mux.HandleFunc("GET /internal/credentials/{id}/status", is.status)
	app.Mux.HandleFunc("POST /internal/credentials/{id}/revoke", is.revoke)
	// Operator only: reached with kubectl port-forward.
	app.Mux.HandleFunc("POST /internal/wallets/{wallet}/block", is.block)
	app.Mux.HandleFunc("DELETE /internal/wallets/{wallet}/block", is.unblock)
	app.Serve()
}

// gauges feeds the board activity dashboard: keys and the wallets that hold
// them, with the operator's own wallets counted apart.
func (is *issuer) gauges(ctx context.Context) (map[string]float64, error) {
	out := map[string]float64{}
	for _, party := range []string{"external", "first_party"} {
		for _, m := range []string{"stump_keys_valid", "stump_wallets_with_valid_key", "stump_keys_issued_24h", "stump_wallets_total"} {
			out[fmt.Sprintf(`%s{party=%q}`, m, party)] = 0
		}
	}
	rows, err := is.db.Query(ctx, `SELECT lower(subject) = ANY($1),
		count(*) FILTER (WHERE revoked_at IS NULL AND expires_at > now()),
		count(DISTINCT lower(subject)) FILTER (WHERE revoked_at IS NULL AND expires_at > now()),
		count(*) FILTER (WHERE issued_at > now() - interval '24 hours'),
		count(DISTINCT lower(subject))
		FROM credentials GROUP BY 1`, stump.FirstParty())
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var first bool
		var valid, wallets, issued, ever int64
		if rows.Scan(&first, &valid, &wallets, &issued, &ever) == nil {
			party := "external"
			if first {
				party = "first_party"
			}
			out[fmt.Sprintf(`stump_keys_valid{party=%q}`, party)] = float64(valid)
			out[fmt.Sprintf(`stump_wallets_with_valid_key{party=%q}`, party)] = float64(wallets)
			out[fmt.Sprintf(`stump_keys_issued_24h{party=%q}`, party)] = float64(issued)
			out[fmt.Sprintf(`stump_wallets_total{party=%q}`, party)] = float64(ever)
		}
	}
	rows.Close()
	var blocked int64
	if err := is.db.QueryRow(ctx, `SELECT count(*) FROM blocked_wallets`).Scan(&blocked); err != nil {
		return out, err
	}
	out[`stump_wallets_blocked`] = float64(blocked)
	return out, nil
}

func (is *issuer) info(w http.ResponseWriter, _ *http.Request) {
	stump.JSON(w, 200, map[string]any{"address": is.signer.Address().Hex(), "eip712_domain": is.domain})
}

type issueRequest struct {
	Subject      string `json:"subject"`
	ChainID      int64  `json:"chain_id"`
	Plan         string `json:"plan"`
	TermsVersion string `json:"terms_version"`
	PaymentRef   string `json:"payment_ref"`
	ValidDays    int    `json:"valid_days"`
}

func (is *issuer) issue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if err := stump.ReadJSON(r, 4096, &req); err != nil {
		stump.Error(w, 400, "bad_request", err.Error())
		return
	}
	if !common.IsHexAddress(req.Subject) || req.ValidDays < 1 || req.ValidDays > 366 || req.PaymentRef == "" {
		stump.Error(w, 400, "bad_request", "subject, valid_days (1-366) and payment_ref are required")
		return
	}
	var blocked bool
	is.db.QueryRow(r.Context(), `SELECT true FROM blocked_wallets WHERE wallet=lower($1)`, req.Subject).Scan(&blocked)
	if blocked {
		stump.Error(w, 403, "wallet_blocked", "this wallet was blocked for abuse")
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	now := time.Now().UTC().Truncate(time.Second)
	c := &cred.Credential{
		ID: hex.EncodeToString(id), Subject: common.HexToAddress(req.Subject).Hex(),
		SubjectChainID: req.ChainID, Plan: req.Plan, TermsVersion: req.TermsVersion,
		PaymentRef: req.PaymentRef, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Duration(req.ValidDays) * 24 * time.Hour).Unix(),
	}
	if err := c.Sign(is.domain, is.signer); err != nil {
		stump.Error(w, 500, "sign_failed", err.Error())
		return
	}
	_, err := is.db.Exec(r.Context(), `INSERT INTO credentials
		(id, subject, subject_chain_id, plan, terms_version, payment_ref, issued_at, expires_at, signature)
		VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7),to_timestamp($8),$9)`,
		c.ID, c.Subject, c.SubjectChainID, c.Plan, c.TermsVersion, c.PaymentRef, c.IssuedAt, c.ExpiresAt, c.Signature)
	if err != nil {
		stump.Error(w, 500, "store_failed", err.Error())
		return
	}
	is.emit(r.Context(), "issued", c)
	stump.JSON(w, 201, map[string]any{"credential": c, "encoded": c.Encode()})
}

func (is *issuer) emit(ctx context.Context, event string, c *cred.Credential) {
	b, _ := json.Marshal(map[string]any{"event": event, "credential": c, "at": time.Now().Unix()})
	if _, err := is.js.Publish(ctx, "stump.issuer.credential."+event, b); err != nil {
		// The row is stored; anchor would miss this event, so log loudly.
		slog.Error("event not published", "event", event, "id", c.ID, "err", err)
	}
}

func (is *issuer) status(w http.ResponseWriter, r *http.Request) {
	var revoked *time.Time
	var expires time.Time
	err := is.db.QueryRow(r.Context(), `SELECT revoked_at, expires_at FROM credentials WHERE id=$1`,
		r.PathValue("id")).Scan(&revoked, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		stump.Error(w, 404, "unknown_credential", "")
		return
	} else if err != nil {
		stump.Error(w, 500, "lookup_failed", err.Error())
		return
	}
	stump.JSON(w, 200, map[string]any{"revoked": revoked != nil, "expires_at": expires.Unix()})
}

func (is *issuer) revoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := stump.ReadJSON(r, 1024, &req); err != nil || req.Reason == "" {
		stump.Error(w, 400, "bad_request", "reason is required")
		return
	}
	var c cred.Credential
	var issued, expires time.Time
	err := is.db.QueryRow(r.Context(), `UPDATE credentials SET revoked_at=now(), revoke_reason=$2
		WHERE id=$1 AND revoked_at IS NULL
		RETURNING id, subject, subject_chain_id, plan, terms_version, payment_ref, issued_at, expires_at, signature`,
		r.PathValue("id"), req.Reason).Scan(&c.ID, &c.Subject, &c.SubjectChainID, &c.Plan, &c.TermsVersion,
		&c.PaymentRef, &issued, &expires, &c.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		stump.Error(w, 404, "unknown_or_already_revoked", "")
		return
	} else if err != nil {
		stump.Error(w, 500, "revoke_failed", err.Error())
		return
	}
	c.IssuedAt, c.ExpiresAt, c.Issuer = issued.Unix(), expires.Unix(), is.signer.Address().Hex()
	is.emit(r.Context(), "revoked", &c)
	stump.JSON(w, 200, map[string]any{"revoked": c.ID})
}

// block revokes every live key of a wallet and refuses new ones.
func (is *issuer) block(w http.ResponseWriter, r *http.Request) {
	wallet := r.PathValue("wallet")
	var req struct {
		Reason string `json:"reason"`
	}
	if !common.IsHexAddress(wallet) {
		stump.Error(w, 400, "bad_wallet", "not an address")
		return
	}
	if err := stump.ReadJSON(r, 1024, &req); err != nil || req.Reason == "" {
		stump.Error(w, 400, "bad_request", "reason is required")
		return
	}
	if _, err := is.db.Exec(r.Context(), `INSERT INTO blocked_wallets (wallet, reason) VALUES (lower($1), $2)
		ON CONFLICT (wallet) DO UPDATE SET reason=$2`, wallet, req.Reason); err != nil {
		stump.Error(w, 500, "block_failed", err.Error())
		return
	}
	rows, err := is.db.Query(r.Context(), `UPDATE credentials SET revoked_at=now(), revoke_reason=$2
		WHERE lower(subject)=lower($1) AND revoked_at IS NULL
		RETURNING id, subject, subject_chain_id, plan, terms_version, payment_ref, issued_at, expires_at, signature`,
		wallet, "blocked: "+req.Reason)
	if err != nil {
		stump.Error(w, 500, "revoke_failed", err.Error())
		return
	}
	var revoked []*cred.Credential
	for rows.Next() {
		var c cred.Credential
		var issued, expires time.Time
		if err := rows.Scan(&c.ID, &c.Subject, &c.SubjectChainID, &c.Plan, &c.TermsVersion,
			&c.PaymentRef, &issued, &expires, &c.Signature); err == nil {
			c.IssuedAt, c.ExpiresAt, c.Issuer = issued.Unix(), expires.Unix(), is.signer.Address().Hex()
			revoked = append(revoked, &c)
		}
	}
	rows.Close()
	ids := []string{}
	for _, c := range revoked {
		is.emit(r.Context(), "revoked", c)
		ids = append(ids, c.ID)
	}
	slog.Info("wallet blocked", "wallet", common.HexToAddress(wallet).Hex(), "revoked", len(ids), "reason", req.Reason)
	stump.JSON(w, 200, map[string]any{"blocked": common.HexToAddress(wallet).Hex(), "revoked": ids})
}

// unblock lets a wallet get keys again; revoked keys stay revoked.
func (is *issuer) unblock(w http.ResponseWriter, r *http.Request) {
	tag, err := is.db.Exec(r.Context(), `DELETE FROM blocked_wallets WHERE wallet=lower($1)`, r.PathValue("wallet"))
	if err != nil {
		stump.Error(w, 500, "unblock_failed", err.Error())
		return
	}
	stump.JSON(w, 200, map[string]any{"unblocked": tag.RowsAffected() > 0})
}

func (is *issuer) lookup(w http.ResponseWriter, r *http.Request) {
	wallet := r.PathValue("wallet")
	if !common.IsHexAddress(wallet) {
		stump.Error(w, 400, "bad_wallet", "not an address")
		return
	}
	rows, err := is.db.Query(r.Context(), `SELECT id, plan, terms_version, issued_at, expires_at, revoked_at
		FROM credentials WHERE lower(subject)=lower($1) ORDER BY issued_at DESC LIMIT 50`, wallet)
	if err != nil {
		stump.Error(w, 500, "lookup_failed", err.Error())
		return
	}
	defer rows.Close()
	type entry struct {
		ID           string `json:"id"`
		Plan         string `json:"plan"`
		TermsVersion string `json:"terms_version"`
		IssuedAt     int64  `json:"issued_at"`
		ExpiresAt    int64  `json:"expires_at"`
		Status       string `json:"status"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		var issued, expires time.Time
		var revoked *time.Time
		if err := rows.Scan(&e.ID, &e.Plan, &e.TermsVersion, &issued, &expires, &revoked); err != nil {
			stump.Error(w, 500, "lookup_failed", err.Error())
			return
		}
		e.IssuedAt, e.ExpiresAt = issued.Unix(), expires.Unix()
		switch {
		case revoked != nil:
			e.Status = "revoked"
		case time.Now().After(expires):
			e.Status = "expired"
		default:
			e.Status = "valid"
		}
		out = append(out, e)
	}
	var blocked bool
	is.db.QueryRow(r.Context(), `SELECT true FROM blocked_wallets WHERE wallet=lower($1)`, wallet).Scan(&blocked)
	stump.JSON(w, 200, map[string]any{"wallet": common.HexToAddress(wallet).Hex(),
		"issuer": is.signer.Address().Hex(), "blocked": blocked, "credentials": out})
}
