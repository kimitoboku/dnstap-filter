package transport

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

func TestStatsHTTPOutput_StartStop(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 10})

	// Record a message.
	mt := dnstap.Message_CLIENT_RESPONSE
	sec := uint64(1700000000)
	msg := &dnstap.Message{
		Type:         &mt,
		QueryAddress: []byte{10, 0, 0, 1},
		QueryTimeSec: &sec,
	}
	dnsMsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Question: []dns.Question{
			{Name: "test.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}
	c.Record(msg, dnsMsg)

	so := NewStatsHTTPOutput(c, "127.0.0.1:19876")
	go so.RunOutputLoop()

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Verify /metrics is reachable.
	resp, err := http.Get("http://127.0.0.1:19876/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "dnstapfilter_matched_frames_total") {
		t.Error("/metrics should contain dnstapfilter_matched_frames_total")
	}

	// Verify / is reachable.
	resp, err = http.Get("http://127.0.0.1:19876/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "dnstap-filter Statistics") {
		t.Error("/ should contain HTML dashboard")
	}

	// Close should shut down cleanly.
	so.Close()
}
