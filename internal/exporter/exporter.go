package exporter

import (
	"context"
	"github.com/example/net-scouter/internal/flow"
)

type Exporter interface {
	Export(context.Context, []flow.Record) error
}
