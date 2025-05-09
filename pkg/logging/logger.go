package logging

import (
	"context"
	"log/slog"
)

type loggerKey struct{}

var loggerEntry loggerKey

func FromContext(ctx context.Context) *slog.Logger {
	u, ok := ctx.Value(loggerEntry).(*slog.Logger)
	if !ok {
		return slog.Default()
	}

	return u
}

func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerEntry, logger)
}
