package postgres

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/tracelog"
)

func TraceLog(ctx context.Context, verb tracelog.LogLevel, msg string, data map[string]any) {
	delta := tracelog.LogLevelInfo          // - slog.LevelInfo (0)
	level := slog.Level((verb - delta) * 4) // slog.perLevel
	slog.Default().Log(ctx, level, msg, slogArgs(data)...)
}

func slogArgs(params map[string]any) []any {
	n := len(params)
	if n == 0 {
		return nil
	}
	args := make([]any, 0, n)
	for param, value := range params {
		// The query "args" (positional parameters) are redacted by shape — binary
		// values become "[Nb]" — so bytea payloads don't flood the logs.
		if param == "args" {
			if positional, ok := value.([]any); ok {
				args = append(args, slogParams(positional))
				continue
			}
		}
		args = append(args, slog.Any(param, value))
	}
	return args
}

func slogParams(params []any) slog.Attr {
	return slog.String("params", slogArray(params))
}

func slogArray[T any](array []T) string {
	if array == nil {
		return "<nil>"
	}
	if len(array) == 0 {
		return "[]"
	}

	var text bytes.Buffer
	sep := "" // value(s) separator
	text.WriteString("[")
	for _, elem := range array {
		text.WriteString(sep)
		if any(elem) == nil {
			text.WriteString("NULL")
			continue
		}
		switch data := any(elem).(type) {
		case []byte:
			{
				if data == nil {
					text.WriteString("NULL")
					break // switch
				}
				fmt.Fprintf(&text, "[%02db]", len(data))
			}
		case [][]byte:
			{
				if data == nil {
					text.WriteString("NULL")
					break // switch
				}
				text.WriteString(slogArray(data))
			}
		default:
			{
				fmt.Fprintf(&text, "%v", data)
			}
		}
		sep = " " // SPACE
	}
	text.WriteString("]")
	return text.String()
}
