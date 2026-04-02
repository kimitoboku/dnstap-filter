package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

func newTestCollector() *stats.Collector {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 10})
	mt := dnstap.Message_CLIENT_RESPONSE
	sec := uint64(1700000000)
	msg := &dnstap.Message{
		Type:         &mt,
		QueryAddress: []byte{192, 168, 1, 1},
		QueryTimeSec: &sec,
	}
	dnsMsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}
	c.Record(msg, dnsMsg)
	return c
}

func TestServerMetricsEndpoint(t *testing.T) {
	c := newTestCollector()
	srv := NewServer(":0", c)

	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Verify Prometheus exposition format contains our metrics.
	for _, want := range []string{
		"dnstapfilter_matched_frames_total",
		"dnstapfilter_queries_by_type_total",
		"dnstapfilter_responses_by_rcode_total",
		"dnstapfilter_top_domains_count",
		"dnstapfilter_top_client_ips_count",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

func TestServerDashboardEndpoint(t *testing.T) {
	c := newTestCollector()
	srv := NewServer(":0", c)

	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	if !strings.Contains(text, "dnstap-filter Statistics") {
		t.Error("/ should contain HTML dashboard title")
	}
	if !strings.Contains(text, "example.com.") {
		t.Error("/ should contain recorded domain")
	}
}
