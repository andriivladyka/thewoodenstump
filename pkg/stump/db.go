package stump

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB connects with the standard PG* variables and sets search_path to the
// service's own schema. Each service's role owns only that schema.
func DB(ctx context.Context, schema string) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		Env("PGHOST", "stump-pg-rw.data.svc.cluster.local"), Env("PGPORT", "5432"),
		Env("PGDATABASE", "stump"), MustEnv("PGUSER"), MustEnv("PGPASSWORD"),
		Env("PGSSLMODE", "require"))
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 5
	var pool *pgxpool.Pool
	err = Retry(ctx, "postgres", func() error {
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			return err
		}
		if err := p.Ping(ctx); err != nil {
			p.Close()
			return err
		}
		pool = p
		return nil
	})
	return pool, err
}

// Migrate runs idempotent DDL statements in order.
func Migrate(ctx context.Context, pool *pgxpool.Pool, stmts ...string) error {
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("migration failed: %w\n%s", err, s)
		}
	}
	return nil
}
