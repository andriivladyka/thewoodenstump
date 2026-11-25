package stump

import (
	"context"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATS connects as this service's user (NATS_USER, NATS_PASSWORD).
func NATS(ctx context.Context, name string) (*nats.Conn, jetstream.JetStream, error) {
	user := Env("NATS_USER", name)
	var nc *nats.Conn
	err := Retry(ctx, "nats", func() error {
		c, err := nats.Connect(Env("NATS_URL", "nats://nats.messaging.svc.cluster.local:4222"),
			NATSOptions(name, user, MustEnv("NATS_PASSWORD"))...)
		nc = c
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(nc)
	return nc, js, err
}

// NATSOptions logs in as user and keeps replies on the user's own inbox
// prefix, the only one the server lets that user subscribe to.
func NATSOptions(name, user, password string) []nats.Option {
	return []nats.Option{
		nats.Name(name),
		nats.UserInfo(user, password),
		nats.CustomInboxPrefix("_INBOX_" + user),
		nats.MaxReconnects(-1),
	}
}
