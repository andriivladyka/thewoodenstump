// anchor collects credential events and, once per interval, records one
// Merkle root covering them through the Chain port (dry run in lab).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/andriivladyka/thewoodenstump/pkg/merkle"
	"github.com/andriivladyka/thewoodenstump/pkg/ports"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

type anchor struct {
	app   *stump.App
	db    *pgxpool.Pool
	chain ports.Chain
}

func main() {
	app := stump.New("anchor")
	ctx := app.Context()
	db, err := stump.DB(ctx, "anchor")
	if err != nil {
		os.Exit(1)
	}
	if err := stump.Migrate(ctx, db,
		`CREATE TABLE IF NOT EXISTS batches (
			id bigserial PRIMARY KEY, root text NOT NULL, leaves int NOT NULL, chain text NOT NULL,
			ref text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS leaves (
			seq bigint PRIMARY KEY, event text NOT NULL, credential_id text NOT NULL, leaf text NOT NULL,
			batch_id bigint REFERENCES batches(id), received_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS leaves_unbatched ON leaves (seq) WHERE batch_id IS NULL`,
	); err != nil {
		app.Log.Error("migrate", "err", err)
		os.Exit(1)
	}
	var chain ports.Chain = ports.DryRun{}
	if c := stump.Env("ANCHOR_CHAIN", "dry-run"); c != "dry-run" {
		app.Log.Error("only the dry-run chain is implemented", "chain", c)
		os.Exit(2)
	}
	a := &anchor{app: app, db: db, chain: chain}

	_, js, err := stump.NATS(ctx, "anchor")
	if err != nil {
		os.Exit(1)
	}
	var cons jetstream.Consumer
	if err := stump.Retry(ctx, "credential stream", func() error {
		cons, err = js.CreateOrUpdateConsumer(ctx, "CREDENTIALS", jetstream.ConsumerConfig{
			Durable: "anchor", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: "stump.issuer.credential.>"})
		return err
	}); err != nil {
		os.Exit(1)
	}
	cc, err := cons.Consume(a.receive)
	if err != nil {
		app.Log.Error("consume", "err", err)
		os.Exit(1)
	}
	defer cc.Stop()
	go a.loop(stump.EnvDuration("ANCHOR_INTERVAL", 168*time.Hour))

	app.Mux.HandleFunc("GET /internal/latest", a.latest)
	app.Serve()
}

func (a *anchor) receive(msg jetstream.Msg) {
	var ev struct {
		Event      string `json:"event"`
		Credential struct {
			ID        string `json:"id"`
			Subject   string `json:"subject"`
			ExpiresAt int64  `json:"expires_at"`
			Signature string `json:"signature"`
		} `json:"credential"`
	}
	meta, err := msg.Metadata()
	if err != nil || json.Unmarshal(msg.Data(), &ev) != nil || ev.Credential.ID == "" {
		a.app.Log.Error("bad credential event; dropping", "err", err)
		msg.Term()
		return
	}
	c := ev.Credential
	leaf := merkle.Leaf(ev.Event, c.ID, c.Subject, strconv.FormatInt(c.ExpiresAt, 10), c.Signature)
	_, err = a.db.Exec(context.Background(), `INSERT INTO leaves (seq, event, credential_id, leaf)
		VALUES ($1,$2,$3,$4) ON CONFLICT (seq) DO NOTHING`,
		meta.Sequence.Stream, ev.Event, c.ID, "0x"+hex.EncodeToString(leaf[:]))
	if err != nil {
		a.app.Log.Error("store leaf", "err", err)
		msg.NakWithDelay(10 * time.Second)
		return
	}
	msg.Ack()
}

func (a *anchor) loop(every time.Duration) {
	a.app.Log.Info("anchoring", "every", every.String(), "chain", a.chain.Name())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-a.app.Context().Done():
			return
		case <-t.C:
			if err := a.batch(a.app.Context()); err != nil {
				a.app.Log.Error("batch failed", "err", err)
			}
		}
	}
}

func (a *anchor) batch(ctx context.Context) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT seq, leaf FROM leaves WHERE batch_id IS NULL ORDER BY seq FOR UPDATE`)
	if err != nil {
		return err
	}
	var seqs []int64
	var leaves [][32]byte
	for rows.Next() {
		var seq int64
		var h string
		rows.Scan(&seq, &h)
		b, _ := hex.DecodeString(h[2:])
		var l [32]byte
		copy(l[:], b)
		seqs, leaves = append(seqs, seq), append(leaves, l)
	}
	rows.Close()
	if len(leaves) == 0 {
		return nil
	}
	root := merkle.Root(leaves)
	ref, err := a.chain.Submit(ctx, root, len(leaves))
	if err != nil {
		return err
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO batches (root, leaves, chain, ref) VALUES ($1,$2,$3,$4) RETURNING id`,
		"0x"+hex.EncodeToString(root[:]), len(leaves), a.chain.Name(), ref).Scan(&id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE leaves SET batch_id=$1 WHERE seq = ANY($2)`, id, seqs); err != nil {
		return err
	}
	a.app.Log.Info("batch recorded", "batch", id, "leaves", len(leaves))
	return tx.Commit(ctx)
}

func (a *anchor) latest(w http.ResponseWriter, r *http.Request) {
	var root, chain, ref string
	var leaves int
	var at time.Time
	err := a.db.QueryRow(r.Context(), `SELECT root, leaves, chain, ref, created_at FROM batches ORDER BY id DESC LIMIT 1`).
		Scan(&root, &leaves, &chain, &ref, &at)
	var pending int
	a.db.QueryRow(r.Context(), `SELECT count(*) FROM leaves WHERE batch_id IS NULL`).Scan(&pending)
	if errors.Is(err, pgx.ErrNoRows) {
		stump.JSON(w, 200, map[string]any{"root": nil, "chain": a.chain.Name(), "pending_leaves": pending})
		return
	} else if err != nil {
		stump.Error(w, 500, "db", err.Error())
		return
	}
	stump.JSON(w, 200, map[string]any{"root": root, "leaves": leaves, "chain": chain, "ref": ref,
		"anchored_at": at.Unix(), "pending_leaves": pending})
}
