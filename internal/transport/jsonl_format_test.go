package transport

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func TestJSONLOutputFormat_Query(t *testing.T) {
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "www.example.com.", dns.TypeA, 0, net.ParseIP("192.168.1.100"))

	out, ok := jsonlOutputFormat(dt)
	if !ok {
		t.Fatal("jsonlOutputFormat returned false for valid query")
	}

	var result jsonlOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}

	if result.Type != "MESSAGE" {
		t.Errorf("type = %q, want MESSAGE", result.Type)
	}
	if result.MessageType != "CLIENT_QUERY" {
		t.Errorf("message_type = %q, want CLIENT_QUERY", result.MessageType)
	}
	if result.Timestamp == "" {
		t.Error("timestamp is empty")
	}
	if result.QueryAddress != "192.168.1.100" {
		t.Errorf("query_address = %q, want 192.168.1.100", result.QueryAddress)
	}
	if result.DNS == nil {
		t.Fatal("dns is nil")
	}
	if result.DNS.QR {
		t.Error("dns.qr = true, want false for query")
	}
	if len(result.DNS.Question) != 1 {
		t.Fatalf("dns.question length = %d, want 1", len(result.DNS.Question))
	}
	if result.DNS.Question[0].Name != "www.example.com." {
		t.Errorf("dns.question[0].name = %q, want www.example.com.", result.DNS.Question[0].Name)
	}
	if result.DNS.Question[0].Type != "A" {
		t.Errorf("dns.question[0].type = %q, want A", result.DNS.Question[0].Type)
	}
}

func TestJSONLOutputFormat_Response(t *testing.T) {
	dt := buildTestDnstap(dnstap.Message_CLIENT_RESPONSE, "bad.example.com.", dns.TypeA, dns.RcodeNameError, nil)

	out, ok := jsonlOutputFormat(dt)
	if !ok {
		t.Fatal("jsonlOutputFormat returned false for valid response")
	}

	var result jsonlOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}

	if result.MessageType != "CLIENT_RESPONSE" {
		t.Errorf("message_type = %q, want CLIENT_RESPONSE", result.MessageType)
	}
	if result.DNS == nil {
		t.Fatal("dns is nil")
	}
	if result.DNS.Rcode != "NXDOMAIN" {
		t.Errorf("dns.rcode = %q, want NXDOMAIN", result.DNS.Rcode)
	}
}

func TestJSONLOutputFormat_WithAnswer(t *testing.T) {
	dtType := dnstap.Dnstap_MESSAGE
	msgType := dnstap.Message_CLIENT_RESPONSE
	sec := uint64(1704067200)

	msg := &dns.Msg{}
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
	}
	packed, _ := msg.Pack()

	sf := dnstap.SocketFamily_INET
	sp := dnstap.SocketProtocol_UDP
	dt := &dnstap.Dnstap{
		Type: &dtType,
		Message: &dnstap.Message{
			Type:            &msgType,
			ResponseTimeSec: &sec,
			ResponseMessage: packed,
			SocketFamily:    &sf,
			SocketProtocol:  &sp,
		},
	}

	out, ok := jsonlOutputFormat(dt)
	if !ok {
		t.Fatal("jsonlOutputFormat returned false")
	}

	var result jsonlOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, out)
	}

	if result.SocketFamily != "INET" {
		t.Errorf("socket_family = %q, want INET", result.SocketFamily)
	}
	if result.SocketProtocol != "UDP" {
		t.Errorf("socket_protocol = %q, want UDP", result.SocketProtocol)
	}
	if result.DNS == nil {
		t.Fatal("dns is nil")
	}
	if len(result.DNS.Answer) != 1 {
		t.Fatalf("dns.answer length = %d, want 1", len(result.DNS.Answer))
	}
	a := result.DNS.Answer[0]
	if a.Name != "www.example.com." {
		t.Errorf("answer name = %q, want www.example.com.", a.Name)
	}
	if a.Type != "A" {
		t.Errorf("answer type = %q, want A", a.Type)
	}
	if a.TTL != 300 {
		t.Errorf("answer ttl = %d, want 300", a.TTL)
	}
	if a.Data != "93.184.216.34" {
		t.Errorf("answer data = %q, want 93.184.216.34", a.Data)
	}
}

func TestJSONLOutputFormat_NilMessage(t *testing.T) {
	dtType := dnstap.Dnstap_MESSAGE
	dt := &dnstap.Dnstap{
		Type:    &dtType,
		Message: nil,
	}
	_, ok := jsonlOutputFormat(dt)
	if ok {
		t.Error("expected false for nil message")
	}
}

func TestJSONLOutputFormat_DNSFlags(t *testing.T) {
	dtType := dnstap.Dnstap_MESSAGE
	msgType := dnstap.Message_CLIENT_RESPONSE
	sec := uint64(1704067200)

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.Authoritative = true
	packed, _ := msg.Pack()

	dt := &dnstap.Dnstap{
		Type: &dtType,
		Message: &dnstap.Message{
			Type:            &msgType,
			ResponseTimeSec: &sec,
			ResponseMessage: packed,
		},
	}

	out, ok := jsonlOutputFormat(dt)
	if !ok {
		t.Fatal("jsonlOutputFormat returned false")
	}

	var result jsonlOutput
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !result.DNS.Flags.RD {
		t.Error("flags.rd = false, want true")
	}
	if !result.DNS.Flags.RA {
		t.Error("flags.ra = false, want true")
	}
	if !result.DNS.Flags.AA {
		t.Error("flags.aa = false, want true")
	}
}

func TestParseOutput_JSONL(t *testing.T) {
	out, err := ParseOutput("jsonl:-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output")
	}
}
