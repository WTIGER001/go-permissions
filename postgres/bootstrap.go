package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type SeedFunc func(ctx context.Context, tx pgx.Tx) error

// Bootstrap ensures schema exists, then runs an optional seed hook.
func (s *Store) Bootstrap(ctx context.Context, seed SeedFunc) error {
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	if seed == nil {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := seed(ctx, tx); err != nil {
		return fmt.Errorf("run seed hook: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit seed transaction: %w", err)
	}

	return nil
}
