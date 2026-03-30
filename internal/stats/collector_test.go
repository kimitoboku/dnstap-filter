package stats

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func makeMessage(qname string, qtype uint16, rcode int, clientIP string, isResponse bool) (*dnstap.Message, *dns.Msg) {
	dnsMsg := &dns.Msg{
		Question: []dns.Question{{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}},
	}
	if isResponse {
		dnsMsg.Rcode = rcode
	}

	var mt dnstap.Message_Type
	if isResponse {
		mt = dnstap.Message_CLIENT_RESPONSE
	} else {
		mt = dnstap.Message_CLIENT_QUERY
	}

	ip := net.ParseIP(clientIP)
	var ipBytes []byte
	if ip4 := ip.To4(); ip4 != nil {
		ipBytes = ip4
	} else {
		ipBytes = ip
	}

	packed, _ := dnsMsg.Pack()
	msg := &dnstap.Message{
		Type:         &mt,
		QueryAddress: ipBytes,
	}
	if isResponse {
		msg.ResponseMessage = packed
	} else {
		msg.QueryMessage = packed
	}

	return msg, dnsMsg
}

func TestCollectorRecord(t *testing.T) {
	c := NewCollector(5)

	msg, dnsMsg := makeMessage("example.com.", dns.TypeA, 0, "10.0.0.1", false)
	c.Record(msg, dnsMsg)

	snap := c.AllTimeSnapshot()
	if snap.TotalFrames != 1 {
		t.Fatalf("expected 1 frame, got %d", snap.TotalFrames)
	}
	if len(snap.TopDomains) != 1 || snap.TopDomains[0].Key != "example.com." {
		t.Fatalf("unexpected top domains: %v", snap.TopDomains)
	}
	if len(snap.QtypeDist) != 1 || snap.QtypeDist[0].Key != "A" {
		t.Fatalf("unexpected qtype dist: %v", snap.QtypeDist)
	}
	if len(snap.ClientIPs) != 1 || snap.ClientIPs[0].Key != "10.0.0.1" {
		t.Fatalf("unexpected client IPs: %v", snap.ClientIPs)
	}
	// Queries should not record rcode.
	if len(snap.RcodeDist) != 0 {
		t.Fatalf("expected no rcode for query, got %v", snap.RcodeDist)
	}
}

func TestCollectorResponseRcode(t *testing.T) {
	c := NewCollector(5)

	msg, dnsMsg := makeMessage("example.com.", dns.TypeA, dns.RcodeNameError, "10.0.0.1", true)
	c.Record(msg, dnsMsg)

	snap := c.AllTimeSnapshot()
	if len(snap.RcodeDist) != 1 || snap.RcodeDist[0].Key != "NXDOMAIN" {
		t.Fatalf("expected NXDOMAIN rcode, got %v", snap.RcodeDist)
	}
}

func TestCollectorTopN(t *testing.T) {
	c := NewCollector(3)

	domains := []string{"a.com.", "b.com.", "c.com.", "d.com.", "e.com."}
	counts := []int{10, 5, 8, 1, 3}
	for i, domain := range domains {
		for j := 0; j < counts[i]; j++ {
			msg, dnsMsg := makeMessage(domain, dns.TypeA, 0, "10.0.0.1", false)
			c.Record(msg, dnsMsg)
		}
	}

	snap := c.AllTimeSnapshot()
	if len(snap.TopDomains) != 3 {
		t.Fatalf("expected 3 top domains, got %d", len(snap.TopDomains))
	}
	// Order should be: a.com. (10), c.com. (8), b.com. (5)
	expected := []string{"a.com.", "c.com.", "b.com."}
	for i, e := range expected {
		if snap.TopDomains[i].Key != e {
			t.Fatalf("position %d: expected %s, got %s", i, e, snap.TopDomains[i].Key)
		}
	}
}

func TestCollectorRotate(t *testing.T) {
	c := NewCollector(5)

	msg1, dnsMsg1 := makeMessage("example.com.", dns.TypeA, 0, "10.0.0.1", false)
	c.Record(msg1, dnsMsg1)

	snap := c.Rotate()
	if snap.TotalFrames != 1 {
		t.Fatalf("expected 1 frame in rotated snapshot, got %d", snap.TotalFrames)
	}

	// After rotation, current window should be empty.
	msg2, dnsMsg2 := makeMessage("test.com.", dns.TypeAAAA, 0, "10.0.0.2", false)
	c.Record(msg2, dnsMsg2)

	snap2 := c.Rotate()
	if snap2.TotalFrames != 1 {
		t.Fatalf("expected 1 frame in second window, got %d", snap2.TotalFrames)
	}

	// All-time should have both.
	allTime := c.AllTimeSnapshot()
	if allTime.TotalFrames != 2 {
		t.Fatalf("expected 2 all-time frames, got %d", allTime.TotalFrames)
	}

	// History should have 2 snapshots.
	history := c.History()
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}
}

func TestCollectorNilDNSMsg(t *testing.T) {
	c := NewCollector(5)

	mt := dnstap.Message_CLIENT_QUERY
	msg := &dnstap.Message{
		Type:         &mt,
		QueryAddress: net.ParseIP("10.0.0.1").To4(),
	}
	c.Record(msg, nil)

	snap := c.AllTimeSnapshot()
	if snap.TotalFrames != 1 {
		t.Fatalf("expected 1 frame, got %d", snap.TotalFrames)
	}
	if len(snap.TopDomains) != 0 {
		t.Fatalf("expected no domains, got %v", snap.TopDomains)
	}
	if len(snap.ClientIPs) != 1 {
		t.Fatalf("expected 1 client IP, got %v", snap.ClientIPs)
	}
}

func TestRenderJSON(t *testing.T) {
	snap := &Snapshot{
		Start:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		TotalFrames: 100,
		TopDomains:  []RankedEntry{{Key: "example.com.", Count: 50}},
		QtypeDist:   []RankedEntry{{Key: "A", Count: 80}},
		RcodeDist:   []RankedEntry{{Key: "NOERROR", Count: 90}},
		ClientIPs:   []RankedEntry{{Key: "10.0.0.1", Count: 100}},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, []*Snapshot{snap}, snap); err != nil {
		t.Fatal(err)
	}

	var result statsReport
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Windows) != 1 {
		t.Fatalf("expected 1 window, got %d", len(result.Windows))
	}
	if result.AllTime.TotalFrames != 100 {
		t.Fatalf("expected 100 all-time frames, got %d", result.AllTime.TotalFrames)
	}
}

func TestRenderXML(t *testing.T) {
	snap := &Snapshot{
		Start:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		TotalFrames: 100,
		TopDomains:  []RankedEntry{{Key: "example.com.", Count: 50}},
		QtypeDist:   []RankedEntry{{Key: "A", Count: 80}},
		RcodeDist:   []RankedEntry{{Key: "NOERROR", Count: 90}},
		ClientIPs:   []RankedEntry{{Key: "10.0.0.1", Count: 100}},
	}

	var buf bytes.Buffer
	if err := RenderXML(&buf, []*Snapshot{snap}, snap); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, `<dnstap-filter-stats>`) {
		t.Fatal("missing root element")
	}
	if !strings.Contains(output, `name="qtype"`) {
		t.Fatal("missing qtype array")
	}
	if !strings.Contains(output, `name="rcode"`) {
		t.Fatal("missing rcode array")
	}

	// Verify XML is well-formed by checking for closing tag.
	if !strings.Contains(output, `</dnstap-filter-stats>`) {
		t.Fatal("missing closing root element")
	}
}

func TestRenderHTML(t *testing.T) {
	snap := &Snapshot{
		Start:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		TotalFrames: 100,
		TopDomains:  []RankedEntry{{Key: "example.com.", Count: 50}},
		QtypeDist:   []RankedEntry{{Key: "A", Count: 80}},
		RcodeDist:   []RankedEntry{{Key: "NOERROR", Count: 90}},
		ClientIPs:   []RankedEntry{{Key: "10.0.0.1", Count: 100}},
	}

	var buf bytes.Buffer
	if err := RenderHTML(&buf, []*Snapshot{snap}, snap); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Fatal("missing DOCTYPE")
	}
	if !strings.Contains(output, "example.com.") {
		t.Fatal("missing domain in output")
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Fatal("missing client IP in output")
	}
}

// verifyProtobufRoundtrip ensures our test helper produces valid protobuf.
func TestMakeMessageProtobuf(t *testing.T) {
	msg, _ := makeMessage("example.com.", dns.TypeA, 0, "10.0.0.1", false)

	dt := &dnstap.Dnstap{
		Type:    dnstap.Dnstap_MESSAGE.Enum(),
		Message: msg,
	}
	data, err := proto.Marshal(dt)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty protobuf data")
	}
}

// suppress unused import warnings
var _ = xml.Header
