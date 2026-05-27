package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PostgreSqlConfig struct {
	Host     string
	Database string
	User     string
	Port     uint16
	Password string
}

func (c PostgreSqlConfig) ConnectionString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", c.User, c.Password, c.Host, c.Port, c.Database)
}

func CreateDefaultPostgresqlContainer(t *testing.T) *PostgreSqlConfig {

	config := PostgreSqlConfig{
		Database: "test-db",
		User:     "postgres",
		Password: "postgres",
	}

	return CreatePostgresqlContainer(t, &config)
}

func CreatePostgresqlContainer(t *testing.T, config *PostgreSqlConfig) *PostgreSqlConfig {

	ctx := context.Background()

	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15.3-alpine"),
		// postgres.WithInitScripts(filepath.Join("..", "testdata", "init-db.sql")),
		postgres.WithDatabase(config.Database),
		postgres.WithUsername(config.User),
		postgres.WithPassword(config.Password),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		t.Skipf("skipping postgres integration test, container unavailable: %v", err)
		return nil
	}

	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate pgContainer: %s", err)
		}
	})

	connstr, _ := pgContainer.ConnectionString(ctx)
	_, err = pgContainer.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pgconfig, err := pgxpool.ParseConfig(connstr)
	if err != nil {
		t.Fatal(err)
	}

	return &PostgreSqlConfig{
		Host:     pgconfig.ConnConfig.Host,
		Database: pgconfig.ConnConfig.Database,
		User:     pgconfig.ConnConfig.User,
		Port:     pgconfig.ConnConfig.Port,
		Password: pgconfig.ConnConfig.Password,
	}
}
