package metrics

import (
	"context"
	"net/http"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewServer creates an HTTP server that serves Prometheus metrics at /metrics
// and a live HTML dashboard at /.
func NewServer(addr string, collector *stats.Collector) *http.Server {
	registry := prometheus.NewRegistry()
	registry.MustRegister(NewExporter(collector))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		windows := collector.History()
		allTime := collector.AllTimeSnapshot()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := stats.RenderHTML(w, windows, allTime); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}

// Shutdown gracefully shuts down the server.
func Shutdown(srv *http.Server, ctx context.Context) error {
	return srv.Shutdown(ctx)
}
