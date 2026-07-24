package postgres

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/tracelog"
)

func TraceLog(ctx context.Context, verb tracelog.LogLevel, msg string, data map[string]any) {
	delta := tracelog.LogLevelInfo          // - slog.LevelInfo (0)
	level := slog.Level((verb - delta) * 4) // slog.perLevel
	slog.Default().Log(ctx, level, msg, slogArgs(data)...)
}

func slogArgs(data map[string]any) []any {
	n := len(data)
	if n == 0 {
		return nil
	}
	args := make([]any, 0, n)
	for key, value := range data {
		args = append(args, slog.Any(key, value))
	}
	return args
}
