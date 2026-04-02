package transport

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kimitoboku/dnstap-filter/internal/metrics"
	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

// StatsHTTPOutput implements dnstap.Output. It starts an HTTP server that
// serves Prometheus metrics at /metrics and a live HTML dashboard at /.
// Frames received on the output channel are discarded (stats recording
// happens upstream via collector.Record in the filter goroutine).
type StatsHTTPOutput struct {
	collector *stats.Collector
	server    *http.Server
	ch        chan []byte
	done      chan struct{}
}

// NewStatsHTTPOutput creates a new StatsHTTPOutput that listens on the given
// address (e.g. ":9090").
func NewStatsHTTPOutput(collector *stats.Collector, addr string) *StatsHTTPOutput {
	return &StatsHTTPOutput{
		collector: collector,
		server:    metrics.NewServer(addr, collector),
		ch:        make(chan []byte, 32),
		done:      make(chan struct{}),
	}
}

func (s *StatsHTTPOutput) GetOutputChannel() chan []byte {
	return s.ch
}

func (s *StatsHTTPOutput) RunOutputLoop() {
	defer close(s.done)

	// Start HTTP server in a goroutine.
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "stats http: %v\n", err)
		}
	}()

	// Drain frames until channel is closed.
	for range s.ch {
	}

	// Shutdown HTTP server gracefully.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "stats http shutdown: %v\n", err)
	}
}

func (s *StatsHTTPOutput) Close() {
	close(s.ch)
	<-s.done
}
