package stump

import (
	"context"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATS connects as this service's user (NATS_USER, NATS_PASSWORD).
func NATS(ctx context.Context, name string) (*nats.Conn, jetstream.JetStream, error) {
	var nc *nats.Conn
	err := Retry(ctx, "nats", func() error {
		c, err := nats.Connect(Env("NATS_URL", "nats://nats.messaging.svc.cluster.local:4222"),
			nats.Name(name),
			nats.UserInfo(Env("NATS_USER", name), MustEnv("NATS_PASSWORD")),
			nats.MaxReconnects(-1))
		nc = c
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(nc)
	return nc, js, err
}
