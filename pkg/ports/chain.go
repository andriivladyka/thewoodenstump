package ports

import (
	"context"
	"encoding/hex"
	"log/slog"
)

// Chain records a Merkle root somewhere others can check it later.
type Chain interface {
	Name() string
	// Submit returns a reference to the record, such as a transaction hash.
	Submit(ctx context.Context, root [32]byte, leaves int) (string, error)
}

// DryRun only logs the root; the caller stores it in Postgres.
type DryRun struct{}

func (DryRun) Name() string { return "dry-run" }
func (DryRun) Submit(_ context.Context, root [32]byte, leaves int) (string, error) {
	ref := "dry-run:0x" + hex.EncodeToString(root[:])
	slog.Info("anchor root (dry run, nothing sent)", "root", ref, "leaves", leaves)
	return ref, nil
}
