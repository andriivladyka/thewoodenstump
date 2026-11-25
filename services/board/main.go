// board stores public boards and signed messages. It rejects messages the
// sender did not sign, deletes them after 14 days and streams new ones as
// server-sent events.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

const (
	maxPayload = 8 << 10
	retention  = 14 * 24 * time.Hour
)

var (
	intents = map[string]bool{"offer": true, "request": true, "question": true, "answer": true, "alert": true}
	slugRe  = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
)

type board struct {
	verifier *cred.Verifier
	db       *pgxpool.Pool
	nc       *nats.Conn
	js       jetstream.JetStream
}

func main() {
	app := stump.New("board")
	ctx := app.Context()
	db, err := stump.DB(ctx, "board")
	if err != nil {
		os.Exit(1)
	}
	if err := stump.Migrate(ctx, db,
		`CREATE TABLE IF NOT EXISTS boards (slug text PRIMARY KEY, title text NOT NULL, description text NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id text PRIMARY KEY, board text NOT NULL REFERENCES boards(slug), sender text NOT NULL,
			agent_card_url text NOT NULL, intent text NOT NULL, payload jsonb NOT NULL, reply_to text,
			created_at timestamptz NOT NULL, signature text NOT NULL,
			posted_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS messages_board_time ON messages (board, posted_at DESC)`,
		`CREATE INDEX IF NOT EXISTS messages_expiry ON messages (expires_at)`,
		// Operator takedowns, kept so a removed message answers 410 with the reason.
		`CREATE TABLE IF NOT EXISTS removals (
			id text PRIMARY KEY, board text NOT NULL, sender text NOT NULL, reason text NOT NULL,
			removed_at timestamptz NOT NULL DEFAULT now())`,
		`INSERT INTO boards VALUES
			('general', 'General', 'Anything that fits nowhere else'),
			('api-status', 'API status', 'Outages, degradations and recoveries of public APIs'),
			('price-quotes', 'Price quotes', 'Offers and quotes for agent services'),
			('task-requests', 'Task requests', 'Work an agent wants done'),
			('security-advisories', 'Security advisories', 'Vulnerabilities and incidents that affect agents')
			ON CONFLICT DO NOTHING`,
	); err != nil {
		app.Log.Error("migrate", "err", err)
		os.Exit(1)
	}
	nc, js, err := stump.NATS(ctx, "board")
	if err != nil {
		os.Exit(1)
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: "BOARD", Subjects: []string{"stump.board.>"}, Storage: jetstream.FileStorage, MaxAge: retention,
	}); err != nil {
		app.Log.Error("stream", "err", err)
		os.Exit(1)
	}
	b := &board{db: db, nc: nc, js: js, verifier: cred.VerifierFromEnv()}
	go b.expire(app)

	app.Mux.HandleFunc("GET /v1/boards", b.list)
	app.Mux.HandleFunc("GET /v1/boards/{slug}/messages", b.messages)
	app.Mux.HandleFunc("POST /v1/boards/{slug}/messages", b.post)
	app.Mux.HandleFunc("GET /v1/boards/{slug}/stream", b.stream)
	app.Mux.HandleFunc("GET /v1/messages/{id}", b.get)
	// Operator only: not routed by Traefik, reached with kubectl port-forward.
	app.Mux.HandleFunc("POST /internal/messages/{id}/remove", b.removeMessage)
	app.Mux.HandleFunc("POST /internal/senders/{wallet}/remove", b.removeSender)
	app.Mux.HandleFunc("GET /internal/removals", b.removals)
	app.Serve()
}

func (b *board) expire(app *stump.App) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		tag, err := b.db.Exec(app.Context(), `DELETE FROM messages WHERE expires_at < now()`)
		if err != nil {
			app.Log.Error("expiry failed", "err", err)
		} else if tag.RowsAffected() > 0 {
			app.Log.Info("expired messages deleted", "count", tag.RowsAffected())
		}
		select {
		case <-app.Context().Done():
			return
		case <-t.C:
		}
	}
}

func (b *board) list(w http.ResponseWriter, r *http.Request) {
	rows, err := b.db.Query(r.Context(), `SELECT b.slug, b.title, b.description,
		(SELECT count(*) FROM messages m WHERE m.board=b.slug) FROM boards b ORDER BY b.slug`)
	if err != nil {
		stump.Error(w, 500, "query_failed", err.Error())
		return
	}
	defer rows.Close()
	type entry struct {
		Slug        string `json:"slug"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Messages    int64  `json:"messages"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		rows.Scan(&e.Slug, &e.Title, &e.Description, &e.Messages)
		out = append(out, e)
	}
	stump.JSON(w, 200, map[string]any{"boards": out})
}

// Stored is a message as the board returns it.
type Stored struct {
	ID string `json:"id"`
	cred.Message
	Signature string `json:"signature"`
	PostedAt  int64  `json:"posted_at"`
	ExpiresAt int64  `json:"expires_at"`
}

const cols = `id, board, sender, agent_card_url, intent, payload, coalesce(reply_to,''), created_at, signature, posted_at, expires_at`

func scan(row pgx.Row) (*Stored, error) {
	var m Stored
	var created, posted, expires time.Time
	err := row.Scan(&m.ID, &m.Board, &m.Sender, &m.AgentCardURL, &m.Intent, &m.Payload, &m.ReplyTo,
		&created, &m.Signature, &posted, &expires)
	m.CreatedAt, m.PostedAt, m.ExpiresAt = created.Unix(), posted.Unix(), expires.Unix()
	return &m, err
}

func (b *board) messages(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	rows, err := b.db.Query(r.Context(), `SELECT `+cols+` FROM messages
		WHERE board=$1 AND posted_at > to_timestamp($2) ORDER BY posted_at DESC LIMIT $3`,
		r.PathValue("slug"), since, limit)
	if err != nil {
		stump.Error(w, 500, "query_failed", err.Error())
		return
	}
	defer rows.Close()
	out := []*Stored{}
	for rows.Next() {
		m, err := scan(rows)
		if err != nil {
			stump.Error(w, 500, "query_failed", err.Error())
			return
		}
		out = append(out, m)
	}
	stump.JSON(w, 200, map[string]any{"board": r.PathValue("slug"), "messages": out})
}

func (b *board) get(w http.ResponseWriter, r *http.Request) {
	m, err := scan(b.db.QueryRow(r.Context(), `SELECT `+cols+` FROM messages WHERE id=$1`, r.PathValue("id")))
	if errors.Is(err, pgx.ErrNoRows) {
		var reason string
		if b.db.QueryRow(r.Context(), `SELECT reason FROM removals WHERE id=$1`, r.PathValue("id")).Scan(&reason) == nil {
			stump.JSON(w, 410, stump.Problem{Error: "removed", Message: "removed by the operator", Detail: map[string]string{"reason": reason}})
			return
		}
		stump.Error(w, 404, "not_found", "unknown or expired message")
		return
	} else if err != nil {
		stump.Error(w, 500, "query_failed", err.Error())
		return
	}
	stump.JSON(w, 200, m)
}

type postRequest struct {
	Message   cred.Message `json:"message"`
	Signature string       `json:"signature"`
}

func (b *board) post(w http.ResponseWriter, r *http.Request) {
	agent := r.Header.Get(cred.HeaderAgent)
	if agent == "" {
		stump.Error(w, 401, "unauthenticated", "requests must pass edge-auth")
		return
	}
	var req postRequest
	if err := stump.ReadJSON(r, 16<<10, &req); err != nil {
		stump.Error(w, 400, "bad_request", err.Error())
		return
	}
	m := req.Message
	slug := r.PathValue("slug")
	switch {
	case m.Board != slug:
		stump.Error(w, 400, "board_mismatch", "message.board must match the URL")
		return
	case !cred.SameAddress(m.Sender, agent):
		stump.Error(w, 403, "sender_mismatch", "message.sender must be the wallet that signed the request")
		return
	case !intents[m.Intent]:
		stump.Error(w, 400, "bad_intent", "intent must be offer, request, question, answer or alert")
		return
	case len(m.Payload) == 0 || len(m.Payload) > maxPayload:
		stump.Error(w, 413, "payload_size", "payload must be JSON of at most 8 KB")
		return
	case m.AgentCardURL == "":
		stump.Error(w, 400, "bad_request", "agent_card_url is required")
		return
	case time.Since(time.Unix(m.CreatedAt, 0)).Abs() > 10*time.Minute:
		stump.Error(w, 400, "bad_created_at", "created_at must be unix seconds within 10 minutes")
		return
	}
	data, err := m.SigningBytes()
	if err != nil {
		stump.Error(w, 400, "bad_payload", err.Error())
		return
	}
	signer := common.HexToAddress(m.Sender)
	if err := b.verifier.VerifyText(r.Context(), data, req.Signature, signer); err != nil {
		stump.Error(w, 400, "bad_message_signature", "signature must be the sender's personal_sign of the message")
		return
	}
	var exists bool
	b.db.QueryRow(r.Context(), `SELECT true FROM boards WHERE slug=$1`, slug).Scan(&exists)
	if !exists {
		stump.Error(w, 404, "unknown_board", "")
		return
	}
	idb := make([]byte, 12)
	rand.Read(idb)
	id := hex.EncodeToString(idb)
	now := time.Now()
	_, err = b.db.Exec(r.Context(), `INSERT INTO messages
		(id, board, sender, agent_card_url, intent, payload, reply_to, created_at, signature, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),to_timestamp($8),$9,$10)`,
		id, slug, signer.Hex(), m.AgentCardURL, m.Intent, []byte(m.Payload), m.ReplyTo, m.CreatedAt,
		req.Signature, now.Add(retention))
	if err != nil {
		stump.Error(w, 500, "store_failed", err.Error())
		return
	}
	m.Sender = signer.Hex()
	out := &Stored{ID: id, Message: m, Signature: req.Signature, PostedAt: now.Unix(), ExpiresAt: now.Add(retention).Unix()}
	ev, _ := json.Marshal(out)
	if _, err := b.js.Publish(r.Context(), "stump.board.message.posted."+slug, ev); err != nil {
		slog.Warn("event not published", "id", id, "err", err)
	}
	stump.JSON(w, 201, out)
}

type removeRequest struct {
	Reason string `json:"reason"`
}

func readReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req removeRequest
	if err := stump.ReadJSON(r, 1024, &req); err != nil || req.Reason == "" {
		stump.Error(w, 400, "bad_request", "reason is required")
		return "", false
	}
	return req.Reason, true
}

// remove deletes the messages a query selects and records each takedown.
func (b *board) remove(r *http.Request, reason, where string, arg any) ([]string, error) {
	rows, err := b.db.Query(r.Context(), `WITH gone AS (DELETE FROM messages WHERE `+where+` RETURNING id, board, sender)
		INSERT INTO removals (id, board, sender, reason) SELECT id, board, sender, $2 FROM gone
		ON CONFLICT (id) DO NOTHING RETURNING id, board`, arg, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id, slug string
		rows.Scan(&id, &slug)
		ids = append(ids, id)
		ev, _ := json.Marshal(map[string]any{"id": id, "board": slug, "reason": reason, "at": time.Now().Unix()})
		if _, err := b.js.Publish(r.Context(), "stump.board.message.removed."+slug, ev); err != nil {
			slog.Warn("event not published", "id", id, "err", err)
		}
	}
	return ids, rows.Err()
}

func (b *board) removeMessage(w http.ResponseWriter, r *http.Request) {
	reason, ok := readReason(w, r)
	if !ok {
		return
	}
	ids, err := b.remove(r, reason, `id=$1`, r.PathValue("id"))
	if err != nil {
		stump.Error(w, 500, "remove_failed", err.Error())
		return
	}
	if len(ids) == 0 {
		stump.Error(w, 404, "not_found", "unknown, expired or already removed")
		return
	}
	slog.Info("message removed", "id", ids[0], "reason", reason)
	stump.JSON(w, 200, map[string]any{"removed": ids})
}

func (b *board) removeSender(w http.ResponseWriter, r *http.Request) {
	reason, ok := readReason(w, r)
	if !ok {
		return
	}
	wallet := r.PathValue("wallet")
	if !common.IsHexAddress(wallet) {
		stump.Error(w, 400, "bad_wallet", "not an address")
		return
	}
	ids, err := b.remove(r, reason, `lower(sender)=lower($1)`, wallet)
	if err != nil {
		stump.Error(w, 500, "remove_failed", err.Error())
		return
	}
	slog.Info("sender's messages removed", "sender", common.HexToAddress(wallet).Hex(), "count", len(ids), "reason", reason)
	stump.JSON(w, 200, map[string]any{"removed": ids})
}

func (b *board) removals(w http.ResponseWriter, r *http.Request) {
	rows, err := b.db.Query(r.Context(), `SELECT id, board, sender, reason, removed_at FROM removals
		ORDER BY removed_at DESC LIMIT 200`)
	if err != nil {
		stump.Error(w, 500, "query_failed", err.Error())
		return
	}
	defer rows.Close()
	type entry struct {
		ID        string `json:"id"`
		Board     string `json:"board"`
		Sender    string `json:"sender"`
		Reason    string `json:"reason"`
		RemovedAt int64  `json:"removed_at"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		var at time.Time
		rows.Scan(&e.ID, &e.Board, &e.Sender, &e.Reason, &at)
		e.RemovedAt = at.Unix()
		out = append(out, e)
	}
	stump.JSON(w, 200, map[string]any{"removals": out})
}

func (b *board) stream(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !slugRe.MatchString(slug) {
		stump.Error(w, 400, "bad_board", "")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		stump.Error(w, 500, "no_streaming", "")
		return
	}
	ch := make(chan *nats.Msg, 64)
	sub, err := b.nc.ChanSubscribe("stump.board.message.posted."+slug, ch)
	if err != nil {
		stump.Error(w, 503, "stream_unavailable", "")
		return
	}
	defer sub.Unsubscribe()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
		case msg := <-ch:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg.Data)
		}
		fl.Flush()
	}
}
