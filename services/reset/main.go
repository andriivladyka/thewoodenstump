// reset wipes the lab: every service's tables, the NATS streams and the
// edge-auth counters, then restarts the services so they recreate their
// tables and reseed (boards, bots). It refuses to run outside lab.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

var (
	dbRoles = []string{"billing", "issuer", "board", "trust", "anchor"}
	// stream or KV bucket -> the NATS user allowed to manage it
	natsState = [][3]string{{"stream", "CREDENTIALS", "issuer"}, {"stream", "BOARD", "board"}, {"kv", "edge_auth", "edge-auth"}}
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "reset")
	if env := os.Getenv("STUMP_ENVIRONMENT"); env != "lab" {
		log.Error("refusing to reset: this only runs in lab", "environment", env)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	failed := false
	// A new pod's network policy can take a moment to apply, so each step
	// gets a few tries before it counts as failed.
	step := func(what string, f func() (string, error)) {
		var err error
		for try := 0; try < 10; try++ {
			var done string
			if done, err = f(); err == nil {
				log.Info(done)
				return
			}
			time.Sleep(3 * time.Second)
		}
		failed = true
		log.Error("could not "+what, "err", err)
	}
	for _, role := range dbRoles {
		step("drop the tables in schema "+role, func() (string, error) {
			n, err := dropTables(ctx, role)
			return fmt.Sprintf("dropped %d tables in schema %s", n, role), err
		})
	}
	for _, s := range natsState {
		step(fmt.Sprintf("delete NATS %s %s", s[0], s[1]), func() (string, error) {
			return fmt.Sprintf("deleted NATS %s %s", s[0], s[1]), deleteNATS(ctx, s[0], s[1], s[2])
		})
	}
	for _, d := range strings.Fields(stump.Env("RESTART", "")) {
		step("restart "+d, func() (string, error) { return "restarted " + d, restart(ctx, d) })
	}
	if failed {
		log.Error("reset finished with errors")
		os.Exit(1)
	}
	log.Info("lab reset done; services recreate their tables and reseed as they start")
}

func envKey(role, what string) string {
	return "PG_" + strings.ToUpper(strings.ReplaceAll(role, "-", "_")) + "_" + what
}

func dropTables(ctx context.Context, role string) (int, error) {
	dsn := fmt.Sprintf("host=%s dbname=stump user=%s password=%s sslmode=require",
		stump.Env("PGHOST", "stump-pg-rw.data.svc.cluster.local"), os.Getenv(envKey(role, "USER")), os.Getenv(envKey(role, "PASSWORD")))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname=$1 AND tableowner=current_user`, role)
	if err != nil {
		return 0, err
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	for _, t := range tables {
		if _, err := conn.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s.%s CASCADE`,
			pgx.Identifier{role}.Sanitize(), pgx.Identifier{t}.Sanitize())); err != nil {
			return 0, err
		}
	}
	return len(tables), nil
}

func deleteNATS(ctx context.Context, kind, name, user string) error {
	nc, err := nats.Connect(stump.Env("NATS_URL", "nats://nats.messaging.svc.cluster.local:4222"),
		nats.Name("reset"), nats.UserInfo(user, os.Getenv("NATS_"+strings.ToUpper(strings.ReplaceAll(user, "-", "_"))+"_PASSWORD")))
	if err != nil {
		return err
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		return err
	}
	if kind == "kv" {
		err = js.DeleteKeyValue(ctx, name)
		if errors.Is(err, jetstream.ErrBucketNotFound) {
			return nil
		}
		return err
	}
	err = js.DeleteStream(ctx, name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil
	}
	return err
}

// restart does what kubectl rollout restart does, with the pod's own
// service account, which may only patch Deployments in this namespace.
func restart(ctx context.Context, deploy string) error {
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	token, err := os.ReadFile(sa + "token")
	if err != nil {
		return err
	}
	ns, _ := os.ReadFile(sa + "namespace")
	ca, _ := os.ReadFile(sa + "ca.crt")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().UTC().Format(time.RFC3339))
	url := fmt.Sprintf("https://kubernetes.default.svc/apis/apps/v1/namespaces/%s/deployments/%s", ns, deploy)
	req, _ := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader([]byte(patch)))
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("kubernetes answered %d", resp.StatusCode)
	}
	return nil
}
