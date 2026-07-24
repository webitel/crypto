package postgres

// Config is the per-store config block (StoreConfig.Config) for a registry-opened
// Postgres store (cryptostore.OpenStore, scheme "postgres").
type Config struct {

	// DSN is the pgx connection string or URL (postgres://user:pass@host:port/db).
	// It may be empty or partial: pgx fills the rest from the libpq-style
	// environment (PGHOST, PGPORT, PGDATABASE, PGSERVICE/PGSERVICEFILE, PGPASSFILE,
	// PGAPPNAME, …) and applies defaults, so an empty DSN is valid.
	DSN string `json:"dsn,omitempty"`

	// Name identifies the store in status output; defaults to "postgres".
	Name string `json:"name,omitempty"`

	// Schema is the Postgres schema holding the cryptostore_* helper functions
	// (installed by the registry driver); DEFAULT: "public".
	Schema string `json:"schema,omitempty"`
}
