package metrics

import (
	"testing"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kimitoboku/dnstap-filter/internal/stats"
)

func makeMsg(qname string, qtype uint16, rcode int, isResponse bool, clientIP []byte) (*dnstap.Message, *dns.Msg) {
	var mt dnstap.Message_Type
	if isResponse {
		mt = dnstap.Message_CLIENT_RESPONSE
	} else {
		mt = dnstap.Message_CLIENT_QUERY
	}
	sec := uint64(1700000000)
	msg := &dnstap.Message{
		Type:         &mt,
		QueryAddress: clientIP,
		QueryTimeSec: &sec,
	}
	dnsMsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: rcode},
		Question: []dns.Question{
			{Name: qname, Qtype: qtype, Qclass: dns.ClassINET},
		},
	}
	return msg, dnsMsg
}

func TestExporterCollect(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 10})
	e := NewExporter(c)

	// Record some messages.
	msg1, dns1 := makeMsg("example.com.", dns.TypeA, dns.RcodeSuccess, true, []byte{192, 168, 1, 1})
	c.Record(msg1, dns1)

	msg2, dns2 := makeMsg("example.com.", dns.TypeAAAA, dns.RcodeSuccess, true, []byte{192, 168, 1, 1})
	c.Record(msg2, dns2)

	msg3, dns3 := makeMsg("test.org.", dns.TypeA, dns.RcodeNameError, true, []byte{10, 0, 0, 1})
	c.Record(msg3, dns3)

	// Register and gather.
	registry := prometheus.NewRegistry()
	registry.MustRegister(e)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	// Verify metric names exist.
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"dnstapfilter_matched_frames_total",
		"dnstapfilter_queries_by_type_total",
		"dnstapfilter_responses_by_rcode_total",
		"dnstapfilter_top_domains_count",
		"dnstapfilter_top_client_ips_count",
	} {
		if !names[want] {
			t.Errorf("missing metric %q", want)
		}
	}

	// Verify frames total = 3.
	for _, f := range families {
		if f.GetName() == "dnstapfilter_matched_frames_total" {
			if len(f.GetMetric()) != 1 {
				t.Fatalf("expected 1 metric for frames_total, got %d", len(f.GetMetric()))
			}
			val := f.GetMetric()[0].GetCounter().GetValue()
			if val != 3 {
				t.Errorf("frames_total = %v, want 3", val)
			}
		}
	}
}

func TestExporterDescribe(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 10})
	e := NewExporter(c)

	ch := make(chan *prometheus.Desc, 10)
	e.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count != 5 {
		t.Errorf("Describe sent %d descriptors, want 5", count)
	}
}

func TestExporterGather(t *testing.T) {
	c := stats.NewCollector(stats.CollectorOptions{TopN: 10})
	e := NewExporter(c)

	msg, dnsMsg := makeMsg("example.com.", dns.TypeA, dns.RcodeSuccess, true, []byte{192, 168, 1, 1})
	c.Record(msg, dnsMsg)

	registry := prometheus.NewRegistry()
	registry.MustRegister(e)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}
	if len(families) == 0 {
		t.Fatal("expected metrics, got none")
	}
}
