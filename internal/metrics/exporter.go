package metrics

import (
	"github.com/kimitoboku/dnstap-filter/internal/stats"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "dnstapfilter"

// Exporter implements prometheus.Collector. It reads from a stats.Collector
// on each Prometheus scrape and returns current metric values.
type Exporter struct {
	collector *stats.Collector

	framesTotal      *prometheus.Desc
	queriesByType    *prometheus.Desc
	responsesByRcode *prometheus.Desc
	topDomains       *prometheus.Desc
	topClientIPs     *prometheus.Desc
}

// NewExporter creates a new Exporter that reads from the given stats.Collector.
func NewExporter(collector *stats.Collector) *Exporter {
	return &Exporter{
		collector: collector,
		framesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "matched_frames_total"),
			"Total number of filter-matched frames.",
			nil, nil,
		),
		queriesByType: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "queries_by_type_total"),
			"Number of matched queries by DNS type.",
			[]string{"qtype"}, nil,
		),
		responsesByRcode: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "responses_by_rcode_total"),
			"Number of responses by DNS response code.",
			[]string{"rcode"}, nil,
		),
		topDomains: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "top_domains_count"),
			"Query count for top-N queried domains.",
			[]string{"domain"}, nil,
		),
		topClientIPs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "top_client_ips_count"),
			"Query count for top-N client IPs.",
			[]string{"client_ip"}, nil,
		),
	}
}

// Describe sends the metric descriptors to the channel.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.framesTotal
	ch <- e.queriesByType
	ch <- e.responsesByRcode
	ch <- e.topDomains
	ch <- e.topClientIPs
}

// Collect reads the current all-time snapshot from the stats collector
// and sends metric values to the channel.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	snap := e.collector.AllTimeSnapshot()

	ch <- prometheus.MustNewConstMetric(
		e.framesTotal, prometheus.CounterValue, float64(snap.TotalFrames),
	)

	for _, entry := range snap.QtypeDist {
		ch <- prometheus.MustNewConstMetric(
			e.queriesByType, prometheus.CounterValue, float64(entry.Count), entry.Key,
		)
	}

	for _, entry := range snap.RcodeDist {
		ch <- prometheus.MustNewConstMetric(
			e.responsesByRcode, prometheus.CounterValue, float64(entry.Count), entry.Key,
		)
	}

	for _, entry := range snap.TopDomains {
		ch <- prometheus.MustNewConstMetric(
			e.topDomains, prometheus.GaugeValue, float64(entry.Count), entry.Key,
		)
	}

	for _, entry := range snap.ClientIPs {
		ch <- prometheus.MustNewConstMetric(
			e.topClientIPs, prometheus.GaugeValue, float64(entry.Count), entry.Key,
		)
	}
}
