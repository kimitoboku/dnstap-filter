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
	return makeMessageAt(qname, qtype, rcode, clientIP, isResponse, time.Time{})
}

func makeMessageAt(qname string, qtype uint16, rcode int, clientIP string, isResponse bool, ts time.Time) (*dnstap.Message, *dns.Msg) {
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

	if !ts.IsZero() {
		sec := uint64(ts.Unix())
		nsec := uint32(ts.Nanosecond())
		msg.QueryTimeSec = &sec
		msg.QueryTimeNsec = &nsec
	}

	return msg, dnsMsg
}

func TestCollectorRecord(t *testing.T) {
	c := NewCollector(CollectorOptions{TopN: 5})

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
	c := NewCollector(CollectorOptions{TopN: 5})

	msg, dnsMsg := makeMessage("example.com.", dns.TypeA, dns.RcodeNameError, "10.0.0.1", true)
	c.Record(msg, dnsMsg)

	snap := c.AllTimeSnapshot()
	if len(snap.RcodeDist) != 1 || snap.RcodeDist[0].Key != "NXDOMAIN" {
		t.Fatalf("expected NXDOMAIN rcode, got %v", snap.RcodeDist)
	}
}

func TestCollectorTopN(t *testing.T) {
	c := NewCollector(CollectorOptions{TopN: 3})

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
	c := NewCollector(CollectorOptions{TopN: 5})

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
	c := NewCollector(CollectorOptions{TopN: 5})

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

func TestCollectorDomainLabels(t *testing.T) {
	c := NewCollector(CollectorOptions{TopN: 5, DomainLabels: 2})

	for _, qname := range []string{"www.example.com.", "mail.example.com.", "api.example.com."} {
		msg, dnsMsg := makeMessage(qname, dns.TypeA, 0, "10.0.0.1", false)
		c.Record(msg, dnsMsg)
	}
	msg, dnsMsg := makeMessage("other.net.", dns.TypeA, 0, "10.0.0.2", false)
	c.Record(msg, dnsMsg)

	snap := c.AllTimeSnapshot()
	// All three example.com subdomains should be aggregated into "example.com."
	found := false
	for _, e := range snap.TopDomains {
		if e.Key == "example.com." && e.Count == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected example.com. with count 3, got %v", snap.TopDomains)
	}
}

func TestCollectorSubnetPrefix(t *testing.T) {
	c := NewCollector(CollectorOptions{TopN: 5, SubnetPrefix: 24})

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		msg, dnsMsg := makeMessage("example.com.", dns.TypeA, 0, ip, false)
		c.Record(msg, dnsMsg)
	}
	msg, dnsMsg := makeMessage("example.com.", dns.TypeA, 0, "192.168.1.5", false)
	c.Record(msg, dnsMsg)

	snap := c.AllTimeSnapshot()
	found := false
	for _, e := range snap.ClientIPs {
		if e.Key == "10.0.0.0/24" && e.Count == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 10.0.0.0/24 with count 3, got %v", snap.ClientIPs)
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
	if !strings.Contains(output, "chart.js") {
		t.Fatal("missing Chart.js reference")
	}
}

func TestRenderMarkdown(t *testing.T) {
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
	if err := RenderMarkdown(&buf, []*Snapshot{snap}, snap); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "# dnstap-filter Statistics Report") {
		t.Fatal("missing heading")
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

func TestCollectorTimestampWindowRotation(t *testing.T) {
	// Use 60s windows. Send messages spanning 3 windows.
	window := 60 * time.Second
	c := NewCollector(CollectorOptions{TopN: 5, WindowDuration: window})

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Window 1: t=0s, 30s
	msg1, d1 := makeMessageAt("a.com.", dns.TypeA, 0, "10.0.0.1", false, base)
	msg2, d2 := makeMessageAt("b.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(30*time.Second))
	// Window 2: t=61s, 90s
	msg3, d3 := makeMessageAt("c.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(61*time.Second))
	msg4, d4 := makeMessageAt("d.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(90*time.Second))
	// Window 3: t=121s
	msg5, d5 := makeMessageAt("e.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(121*time.Second))

	for _, pair := range [][2]interface{}{{msg1, d1}, {msg2, d2}, {msg3, d3}, {msg4, d4}, {msg5, d5}} {
		c.Record(pair[0].(*dnstap.Message), pair[1].(*dns.Msg))
	}

	// After recording all messages, windows 1 and 2 should have been auto-rotated.
	history := c.History()
	if len(history) != 2 {
		t.Fatalf("expected 2 completed windows, got %d", len(history))
	}
	if history[0].TotalFrames != 2 {
		t.Errorf("window 1: expected 2 frames, got %d", history[0].TotalFrames)
	}
	if history[1].TotalFrames != 2 {
		t.Errorf("window 2: expected 2 frames, got %d", history[1].TotalFrames)
	}

	// Window boundaries should reflect message timestamps.
	if !history[0].Start.Equal(base) {
		t.Errorf("window 1 start: expected %v, got %v", base, history[0].Start)
	}
	if !history[0].End.Equal(base.Add(window)) {
		t.Errorf("window 1 end: expected %v, got %v", base.Add(window), history[0].End)
	}
	if !history[1].Start.Equal(base.Add(window)) {
		t.Errorf("window 2 start: expected %v, got %v", base.Add(window), history[1].Start)
	}

	// All-time snapshot should have all 5 frames.
	allTime := c.AllTimeSnapshot()
	if allTime.TotalFrames != 5 {
		t.Errorf("all-time: expected 5 frames, got %d", allTime.TotalFrames)
	}
}

func TestCollectorTimestampWindowBoundaryExact(t *testing.T) {
	// A message exactly at the window boundary belongs to the next window.
	window := 60 * time.Second
	c := NewCollector(CollectorOptions{TopN: 5, WindowDuration: window})
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	msg1, d1 := makeMessageAt("a.com.", dns.TypeA, 0, "10.0.0.1", false, base)
	msg2, d2 := makeMessageAt("b.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(60*time.Second))
	c.Record(msg1, d1)
	c.Record(msg2, d2)

	history := c.History()
	if len(history) != 1 {
		t.Fatalf("expected 1 completed window, got %d", len(history))
	}
	if history[0].TotalFrames != 1 {
		t.Errorf("expected 1 frame in window 1, got %d", history[0].TotalFrames)
	}
}

func TestCollectorNoTimestamp(t *testing.T) {
	// Messages without timestamps fall back to wall clock; no auto-rotation.
	c := NewCollector(CollectorOptions{TopN: 5, WindowDuration: 60 * time.Second})

	mt := dnstap.Message_CLIENT_QUERY
	msg := &dnstap.Message{Type: &mt}
	c.Record(msg, nil)
	c.Record(msg, nil)

	if len(c.History()) != 0 {
		t.Error("expected no auto-rotation for messages without timestamps")
	}
	snap := c.AllTimeSnapshot()
	if snap.TotalFrames != 2 {
		t.Errorf("expected 2 frames, got %d", snap.TotalFrames)
	}
}

func TestCollectorLastTimestampUsedForRotate(t *testing.T) {
	// Rotate() should use the last message timestamp, not wall clock.
	window := 60 * time.Second
	c := NewCollector(CollectorOptions{TopN: 5, WindowDuration: window})
	ts := time.Date(2024, 6, 1, 12, 0, 30, 0, time.UTC)
	msg, d := makeMessageAt("x.com.", dns.TypeA, 0, "10.0.0.1", false, ts)
	c.Record(msg, d)

	snap := c.Rotate()
	// Snapshot end should equal the last message time.
	if !snap.End.Equal(ts) {
		t.Errorf("Rotate end: expected %v, got %v", ts, snap.End)
	}
}

func TestCollectorAllTimeSnapshotEmpty(t *testing.T) {
	// AllTimeSnapshot on a collector that has never received a message.
	c := NewCollector(CollectorOptions{TopN: 5})
	snap := c.AllTimeSnapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.TotalFrames != 0 {
		t.Errorf("expected 0 frames, got %d", snap.TotalFrames)
	}
}

func TestCollectorRotateEmpty(t *testing.T) {
	// Rotate on a collector that has never received a message.
	c := NewCollector(CollectorOptions{TopN: 5})
	snap := c.Rotate()
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.TotalFrames != 0 {
		t.Errorf("expected 0 frames, got %d", snap.TotalFrames)
	}
}

func TestMessageTimeWithNsec(t *testing.T) {
	// Verify that QueryTimeNsec is included in messageTime.
	sec := uint64(1704067200)
	nsec := uint32(500_000_000) // 0.5s
	mt := dnstap.Message_CLIENT_QUERY
	msg := &dnstap.Message{
		Type:          &mt,
		QueryTimeSec:  &sec,
		QueryTimeNsec: &nsec,
	}
	got := messageTime(msg)
	want := time.Unix(int64(sec), int64(nsec)).UTC()
	if !got.Equal(want) {
		t.Errorf("messageTime: got %v, want %v", got, want)
	}
}

func TestMessageTimeResponseNsec(t *testing.T) {
	// Verify ResponseTimeSec/Nsec path.
	sec := uint64(1704067200)
	nsec := uint32(100_000_000)
	mt := dnstap.Message_CLIENT_RESPONSE
	msg := &dnstap.Message{
		Type:             &mt,
		ResponseTimeSec:  &sec,
		ResponseTimeNsec: &nsec,
	}
	got := messageTime(msg)
	want := time.Unix(int64(sec), int64(nsec)).UTC()
	if !got.Equal(want) {
		t.Errorf("messageTime: got %v, want %v", got, want)
	}
}

func TestMessageTimeNoFields(t *testing.T) {
	mt := dnstap.Message_CLIENT_QUERY
	msg := &dnstap.Message{Type: &mt}
	got := messageTime(msg)
	if !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}

func TestCollectorMaxHistory(t *testing.T) {
	// With MaxHistory=1:
	//   - Window 1 rotated → history=[w1], len=1 ≤ 1, no trim yet.
	//   - Window 2 rotated → history=[w1,w2], len=2 > 1, trim to [w2].
	// AllTimeSnapshot should reflect only w2 + current, not w1.
	winDur := 60 * time.Second
	c := NewCollector(CollectorOptions{TopN: 5, WindowDuration: winDur, MaxHistory: 1})
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Window 1 (t=0..59s): 3 frames of "w1.com."
	for k := 0; k < 3; k++ {
		msg, d := makeMessageAt("w1.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(time.Duration(k)*10*time.Second))
		c.Record(msg, d)
	}
	// Window 2 (t=60..119s): 2 frames of "w2.com." — triggers rotation of window 1.
	for k := 0; k < 2; k++ {
		msg, d := makeMessageAt("w2.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(60*time.Second+time.Duration(k)*10*time.Second))
		c.Record(msg, d)
	}
	// Window 3 (t=120s): 1 frame — triggers rotation of window 2, evicts window 1.
	msg, d := makeMessageAt("w3.com.", dns.TypeA, 0, "10.0.0.1", false, base.Add(120*time.Second))
	c.Record(msg, d)

	// History should have exactly 1 entry (only window 2 retained).
	history := c.History()
	if len(history) != 1 {
		t.Fatalf("expected 1 history entry with MaxHistory=1, got %d", len(history))
	}

	// AllTimeSnapshot must NOT include evicted window 1 (3 frames).
	// Retained: window 2 (2 frames) + current window 3 (1 frame) = 3.
	allTime := c.AllTimeSnapshot()
	if allTime.TotalFrames != 3 {
		t.Errorf("all-time after eviction: expected 3 frames (w2+current), got %d", allTime.TotalFrames)
	}

	// Evicted window 1 domain "w1.com." should not appear in all-time.
	for _, e := range allTime.TopDomains {
		if e.Key == "w1.com." {
			t.Errorf("evicted domain w1.com. should not appear in AllTimeSnapshot, got %v", allTime.TopDomains)
		}
	}
}

func TestCollectorMaxHistoryRotate(t *testing.T) {
	c := NewCollector(CollectorOptions{TopN: 5, MaxHistory: 1})
	msg1, d1 := makeMessage("a.com.", dns.TypeA, 0, "10.0.0.1", false)
	c.Record(msg1, d1)
	c.Rotate()

	msg2, d2 := makeMessage("b.com.", dns.TypeA, 0, "10.0.0.1", false)
	c.Record(msg2, d2)
	c.Rotate()

	// After 2 rotations with MaxHistory=1, only the latest snapshot is kept.
	if len(c.History()) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(c.History()))
	}
}

func TestAllTimeSnapshotAggregatesFromHistory(t *testing.T) {
	// Verify that AllTimeSnapshot correctly aggregates across rotated windows.
	c := NewCollector(CollectorOptions{TopN: 5})
	msg1, d1 := makeMessage("a.com.", dns.TypeA, 0, "10.0.0.1", false)
	c.Record(msg1, d1)
	c.Rotate()

	msg2, d2 := makeMessage("b.com.", dns.TypeAAAA, 0, "10.0.0.2", false)
	c.Record(msg2, d2)
	// Do NOT rotate — b.com. is in the current in-progress window.

	allTime := c.AllTimeSnapshot()
	if allTime.TotalFrames != 2 {
		t.Fatalf("expected 2 total frames, got %d", allTime.TotalFrames)
	}

	// Both domains should appear.
	domains := make(map[string]bool)
	for _, e := range allTime.TopDomains {
		domains[e.Key] = true
	}
	if !domains["a.com."] {
		t.Error("a.com. should appear in AllTimeSnapshot (from history)")
	}
	if !domains["b.com."] {
		t.Error("b.com. should appear in AllTimeSnapshot (from current window)")
	}

	// Both qtypes should appear.
	qtypes := make(map[string]uint64)
	for _, e := range allTime.QtypeDist {
		qtypes[e.Key] = e.Count
	}
	if qtypes["A"] != 1 {
		t.Errorf("expected A count=1, got %d", qtypes["A"])
	}
	if qtypes["AAAA"] != 1 {
		t.Errorf("expected AAAA count=1, got %d", qtypes["AAAA"])
	}
}

// suppress unused import warnings
var _ = xml.Header
