// trust stores signed vouches and flags between key-holders and finds
// vouch paths of up to 3 hops. It does not decide who is trusted: callers
// pick their own anchors and weigh the paths.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

const (
	maxActiveVouches = 5
	maxHops          = 3
)

var (
	scopeRe = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	reasons = map[string]bool{"spam": true, "scam": true, "malware": true, "prompt-injection": true, "harassment": true, "impersonation": true, "other": true}
)

type trust struct {
	db *pgxpool.Pool
	nc *nats.Conn
}

func main() {
	app := stump.New("trust")
	ctx := app.Context()
	db, err := stump.DB(ctx, "trust")
	if err != nil {
		os.Exit(1)
	}
	if err := stump.Migrate(ctx, db,
		`CREATE TABLE IF NOT EXISTS vouches (
			id bigserial PRIMARY KEY, voucher text NOT NULL, subject text NOT NULL, scope text NOT NULL,
			expires_at timestamptz NOT NULL, nonce text NOT NULL, signature text NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
			UNIQUE (voucher, nonce))`,
		`CREATE INDEX IF NOT EXISTS vouches_voucher ON vouches (voucher) WHERE revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS vouches_subject ON vouches (subject) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS flags (
			id bigserial PRIMARY KEY, flagger text NOT NULL, subject text NOT NULL, reason text NOT NULL,
			note text NOT NULL, signature text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS flags_subject ON flags (subject)`,
	); err != nil {
		app.Log.Error("migrate", "err", err)
		os.Exit(1)
	}
	nc, _, err := stump.NATS(ctx, "trust")
	if err != nil {
		os.Exit(1)
	}
	t := &trust{db: db, nc: nc}
	app.Mux.HandleFunc("POST /v1/vouches", t.vouch)
	app.Mux.HandleFunc("GET /v1/vouches", t.listVouches)
	app.Mux.HandleFunc("DELETE /v1/vouches/{id}", t.revoke)
	app.Mux.HandleFunc("POST /v1/flags", t.flag)
	app.Mux.HandleFunc("GET /v1/flags", t.listFlags)
	app.Mux.HandleFunc("GET /v1/trust-paths", t.paths)
	app.Serve()
}

func norm(a string) string { return common.HexToAddress(a).Hex() }

func (t *trust) publish(subject string, v any) {
	b, _ := json.Marshal(v)
	if err := t.nc.Publish(subject, b); err != nil {
		slog.Warn("event not published", "subject", subject, "err", err)
	}
}

func (t *trust) vouch(w http.ResponseWriter, r *http.Request) {
	agent := r.Header.Get(cred.HeaderAgent)
	var req struct {
		Vouch     cred.Vouch `json:"vouch"`
		Signature string     `json:"signature"`
	}
	if err := stump.ReadJSON(r, 4096, &req); err != nil {
		stump.Error(w, 400, "bad_request", err.Error())
		return
	}
	v := req.Vouch
	switch {
	case agent == "" || !cred.SameAddress(v.Voucher, agent):
		stump.Error(w, 403, "voucher_mismatch", "vouch.voucher must be the wallet that signed the request")
		return
	case !common.IsHexAddress(v.Subject) || cred.SameAddress(v.Subject, v.Voucher):
		stump.Error(w, 400, "bad_subject", "subject must be another wallet")
		return
	case !scopeRe.MatchString(v.Scope):
		stump.Error(w, 400, "bad_scope", "scope is a short tag such as reliable-data or honest-posting")
		return
	case v.ExpiresAt <= time.Now().Unix() || v.ExpiresAt > time.Now().Add(366*24*time.Hour).Unix():
		stump.Error(w, 400, "bad_expiry", "expires_at must be within the next year")
		return
	case v.Nonce == "" || len(v.Nonce) > 64:
		stump.Error(w, 400, "bad_nonce", "")
		return
	}
	if s, err := cred.RecoverText(v.SigningBytes(), req.Signature); err != nil || !cred.SameAddress(s.Hex(), v.Voucher) {
		stump.Error(w, 400, "bad_vouch_signature", "signature must be the voucher's personal_sign of the vouch")
		return
	}
	tx, err := t.db.Begin(r.Context())
	if err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	// Serialise per voucher so two requests cannot both pass the limit.
	tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, norm(v.Voucher))
	var active int
	tx.QueryRow(r.Context(), `SELECT count(*) FROM vouches WHERE voucher=$1 AND revoked_at IS NULL AND expires_at > now()`,
		norm(v.Voucher)).Scan(&active)
	if active >= maxActiveVouches {
		stump.Error(w, 409, "vouch_limit", "a key may have at most 5 active vouches; revoke one first")
		return
	}
	var id int64
	err = tx.QueryRow(r.Context(), `INSERT INTO vouches (voucher, subject, scope, expires_at, nonce, signature)
		VALUES ($1,$2,$3,to_timestamp($4),$5,$6) RETURNING id`,
		norm(v.Voucher), norm(v.Subject), v.Scope, v.ExpiresAt, v.Nonce, req.Signature).Scan(&id)
	if err != nil {
		stump.Error(w, 409, "duplicate_vouch", "this nonce was already used")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	t.publish("stump.trust.vouch.created", map[string]any{"id": id, "vouch": v})
	stump.JSON(w, 201, map[string]any{"id": id, "vouch": v, "signature": req.Signature, "active": active + 1})
}

func (t *trust) revoke(w http.ResponseWriter, r *http.Request) {
	agent := r.Header.Get(cred.HeaderAgent)
	tag, err := t.db.Exec(r.Context(), `UPDATE vouches SET revoked_at=now() WHERE id=$1 AND voucher=$2 AND revoked_at IS NULL`,
		r.PathValue("id"), norm(agent))
	if err != nil || tag.RowsAffected() == 0 {
		stump.Error(w, 404, "not_found", "no active vouch with this id from your wallet")
		return
	}
	t.publish("stump.trust.vouch.revoked", map[string]any{"id": r.PathValue("id"), "voucher": norm(agent)})
	stump.JSON(w, 200, map[string]any{"revoked": r.PathValue("id")})
}

func (t *trust) listVouches(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	where, arg := "subject=$1", q.Get("subject")
	if q.Get("voucher") != "" {
		where, arg = "voucher=$1", q.Get("voucher")
	}
	if !common.IsHexAddress(arg) {
		stump.Error(w, 400, "bad_request", "give subject= or voucher= as a wallet address")
		return
	}
	rows, err := t.db.Query(r.Context(), `SELECT id, voucher, subject, scope, extract(epoch from expires_at)::bigint,
		nonce, signature FROM vouches WHERE `+where+` AND revoked_at IS NULL AND expires_at > now() ORDER BY id DESC LIMIT 100`, norm(arg))
	if err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var v cred.Vouch
		var sig string
		rows.Scan(&id, &v.Voucher, &v.Subject, &v.Scope, &v.ExpiresAt, &v.Nonce, &sig)
		out = append(out, map[string]any{"id": id, "vouch": v, "signature": sig})
	}
	stump.JSON(w, 200, map[string]any{"vouches": out})
}

func (t *trust) flag(w http.ResponseWriter, r *http.Request) {
	agent := r.Header.Get(cred.HeaderAgent)
	var req struct {
		Flag      cred.Flag `json:"flag"`
		Signature string    `json:"signature"`
	}
	if err := stump.ReadJSON(r, 4096, &req); err != nil {
		stump.Error(w, 400, "bad_request", err.Error())
		return
	}
	f := req.Flag
	switch {
	case agent == "" || !cred.SameAddress(f.Flagger, agent):
		stump.Error(w, 403, "flagger_mismatch", "flag.flagger must be the wallet that signed the request")
		return
	case !common.IsHexAddress(f.Subject):
		stump.Error(w, 400, "bad_subject", "")
		return
	case !reasons[f.Reason]:
		stump.Error(w, 400, "bad_reason", "reason must be one of spam, scam, malware, prompt-injection, harassment, impersonation, other")
		return
	case len(f.Note) > 500:
		stump.Error(w, 400, "note_too_long", "")
		return
	}
	if s, err := cred.RecoverText(f.SigningBytes(), req.Signature); err != nil || !cred.SameAddress(s.Hex(), f.Flagger) {
		stump.Error(w, 400, "bad_flag_signature", "")
		return
	}
	var id int64
	if err := t.db.QueryRow(r.Context(), `INSERT INTO flags (flagger, subject, reason, note, signature)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`, norm(f.Flagger), norm(f.Subject), f.Reason, f.Note, req.Signature).Scan(&id); err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	t.publish("stump.trust.flag.created", map[string]any{"id": id, "flag": f})
	stump.JSON(w, 201, map[string]any{"id": id})
}

func (t *trust) listFlags(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	if !common.IsHexAddress(subject) {
		stump.Error(w, 400, "bad_request", "give subject= as a wallet address")
		return
	}
	rows, err := t.db.Query(r.Context(), `SELECT id, flagger, reason, note, signature, extract(epoch from created_at)::bigint
		FROM flags WHERE subject=$1 ORDER BY id DESC LIMIT 100`, norm(subject))
	if err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, at int64
		var flagger, reason, note, sig string
		rows.Scan(&id, &flagger, &reason, &note, &sig, &at)
		out = append(out, map[string]any{"id": id, "flagger": flagger, "reason": reason, "note": note, "signature": sig, "created_at": at})
	}
	stump.JSON(w, 200, map[string]any{"subject": norm(subject), "flags": out})
}

// paths returns every vouch path from one of the anchors to the target, up
// to 3 hops, using active vouches only.
func (t *trust) paths(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	to := q.Get("to")
	var anchors []string
	for _, a := range strings.Split(q.Get("from"), ",") {
		if common.IsHexAddress(a) {
			anchors = append(anchors, norm(a))
		}
	}
	if !common.IsHexAddress(to) || len(anchors) == 0 || len(anchors) > 20 {
		stump.Error(w, 400, "bad_request", "give from= (1-20 comma-separated anchor wallets) and to=")
		return
	}
	rows, err := t.db.Query(r.Context(), `SELECT id, voucher, subject, scope FROM vouches
		WHERE revoked_at IS NULL AND expires_at > now()`)
	if err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	type edge struct {
		ID      int64  `json:"vouch_id"`
		Voucher string `json:"voucher"`
		Subject string `json:"subject"`
		Scope   string `json:"scope"`
	}
	out := map[string][]edge{}
	for rows.Next() {
		var e edge
		rows.Scan(&e.ID, &e.Voucher, &e.Subject, &e.Scope)
		out[e.Voucher] = append(out[e.Voucher], e)
	}
	rows.Close()
	target := norm(to)
	var found [][]edge
	var walk func(at string, path []edge, seen map[string]bool)
	walk = func(at string, path []edge, seen map[string]bool) {
		if len(found) >= 50 {
			return
		}
		if at == target && len(path) > 0 {
			found = append(found, append([]edge(nil), path...))
			return
		}
		if len(path) == maxHops {
			return
		}
		for _, e := range out[at] {
			if seen[e.Subject] {
				continue
			}
			seen[e.Subject] = true
			walk(e.Subject, append(path, e), seen)
			delete(seen, e.Subject)
		}
	}
	for _, a := range anchors {
		walk(a, nil, map[string]bool{a: true})
	}
	if found == nil {
		found = [][]edge{}
	}
	stump.JSON(w, 200, map[string]any{"to": target, "from": anchors, "max_hops": maxHops, "paths": found})
}
