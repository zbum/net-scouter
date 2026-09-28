package exporter

import (
	"context"
	"github.com/zbum/net-scouter/internal/flow"
)

type Exporter interface {
	Export(context.Context, []flow.Record) error
}
