package transport

import (
	"net"
	"strings"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// buildTestDnstap constructs a dnstap message for testing.
func buildTestDnstap(msgType dnstap.Message_Type, qname string, qtype uint16, rcode int, queryAddr net.IP) *dnstap.Dnstap {
	dtType := dnstap.Dnstap_MESSAGE

	msg := &dns.Msg{}
	msg.SetQuestion(qname, qtype)
	msg.Rcode = rcode

	packed, err := msg.Pack()
	if err != nil {
		panic(err)
	}

	m := &dnstap.Message{
		Type: &msgType,
	}

	sec := uint64(1704067200) // 2024-01-01 00:00:00 UTC
	if isResponseType(msgType) {
		m.ResponseTimeSec = &sec
		m.ResponseMessage = packed
		m.ResponseAddress = queryAddr
	} else {
		m.QueryTimeSec = &sec
		m.QueryMessage = packed
	}

	if queryAddr != nil {
		m.QueryAddress = queryAddr
	}

	return &dnstap.Dnstap{
		Type:    &dtType,
		Message: m,
	}
}

func TestParseStdoutFields(t *testing.T) {
	tests := []struct {
		spec    string
		want    int // expected number of fields
		wantErr bool
	}{
		{"", len(defaultFields), false},
		{"time,name,type", 3, false},
		{"time,qr,name,type,rcode,ip,msgtype", 7, false},
		{"bogus", 0, true},
		{"time,,name", 0, true},
		{"time,bogus", 0, true},
	}
	for _, tt := range tests {
		fields, err := parseStdoutFields(tt.spec)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseStdoutFields(%q): expected error", tt.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseStdoutFields(%q): unexpected error: %v", tt.spec, err)
			continue
		}
		if len(fields) != tt.want {
			t.Errorf("parseStdoutFields(%q): got %d fields, want %d", tt.spec, len(fields), tt.want)
		}
	}
}

func TestIsResponseType(t *testing.T) {
	queries := []dnstap.Message_Type{
		dnstap.Message_AUTH_QUERY,
		dnstap.Message_RESOLVER_QUERY,
		dnstap.Message_CLIENT_QUERY,
		dnstap.Message_FORWARDER_QUERY,
	}
	responses := []dnstap.Message_Type{
		dnstap.Message_AUTH_RESPONSE,
		dnstap.Message_RESOLVER_RESPONSE,
		dnstap.Message_CLIENT_RESPONSE,
		dnstap.Message_FORWARDER_RESPONSE,
	}
	for _, mt := range queries {
		if isResponseType(mt) {
			t.Errorf("isResponseType(%v) = true, want false", mt)
		}
	}
	for _, mt := range responses {
		if !isResponseType(mt) {
			t.Errorf("isResponseType(%v) = false, want true", mt)
		}
	}
}

func TestDefaultQueryFormat_Query(t *testing.T) {
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "www.example.com.", dns.TypeA, 0, nil)
	buf, _ := proto.Marshal(dt)
	dt2 := &dnstap.Dnstap{}
	proto.Unmarshal(buf, dt2)

	out, ok := defaultQueryFormat(dt)
	if !ok {
		t.Fatal("defaultQueryFormat returned false for valid query")
	}
	line := string(out)
	if !strings.Contains(line, " Q ") {
		t.Errorf("expected Q indicator in output, got: %s", line)
	}
	if !strings.Contains(line, "www.example.com.") {
		t.Errorf("expected query name in output, got: %s", line)
	}
	if !strings.Contains(line, " A") {
		t.Errorf("expected query type A in output, got: %s", line)
	}
	// Query should not have RCODE
	if strings.Contains(line, "NOERROR") || strings.Contains(line, "NXDOMAIN") {
		t.Errorf("query should not have RCODE in output, got: %s", line)
	}
}

func TestDefaultQueryFormat_Response(t *testing.T) {
	dt := buildTestDnstap(dnstap.Message_CLIENT_RESPONSE, "bad.example.com.", dns.TypeA, dns.RcodeNameError, nil)

	out, ok := defaultQueryFormat(dt)
	if !ok {
		t.Fatal("defaultQueryFormat returned false for valid response")
	}
	line := string(out)
	if !strings.Contains(line, " R ") {
		t.Errorf("expected R indicator in output, got: %s", line)
	}
	if !strings.Contains(line, "bad.example.com.") {
		t.Errorf("expected query name in output, got: %s", line)
	}
	if !strings.Contains(line, "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN rcode in output, got: %s", line)
	}
}

func TestDefaultQueryFormat_ResponseNoError(t *testing.T) {
	dt := buildTestDnstap(dnstap.Message_CLIENT_RESPONSE, "www.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil)

	out, ok := defaultQueryFormat(dt)
	if !ok {
		t.Fatal("defaultQueryFormat returned false for valid response")
	}
	line := string(out)
	if !strings.Contains(line, " R ") {
		t.Errorf("expected R indicator in output, got: %s", line)
	}
	if !strings.Contains(line, "NOERROR") {
		t.Errorf("expected NOERROR rcode in output, got: %s", line)
	}
}

func TestNewStdoutFormatFunc_CustomFields(t *testing.T) {
	fn := newStdoutFormatFunc([]stdoutField{fieldName, fieldType})
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "example.com.", dns.TypeMX, 0, nil)

	out, ok := fn(dt)
	if !ok {
		t.Fatal("format func returned false")
	}
	line := strings.TrimSpace(string(out))
	// Should only contain name and type, no timestamp
	if strings.Contains(line, "2024") {
		t.Errorf("expected no timestamp in output, got: %s", line)
	}
	if line != "example.com. MX" {
		t.Errorf("expected 'example.com. MX', got: %s", line)
	}
}

func TestNewStdoutFormatFunc_WithIP(t *testing.T) {
	fn := newStdoutFormatFunc([]stdoutField{fieldIP, fieldName})
	ip := net.ParseIP("192.168.1.100")
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "test.example.com.", dns.TypeA, 0, ip)

	out, ok := fn(dt)
	if !ok {
		t.Fatal("format func returned false")
	}
	line := strings.TrimSpace(string(out))
	if !strings.Contains(line, "192.168.1.100") {
		t.Errorf("expected IP in output, got: %s", line)
	}
}

func TestNewStdoutFormatFunc_MsgType(t *testing.T) {
	fn := newStdoutFormatFunc([]stdoutField{fieldMsgType, fieldName})
	dt := buildTestDnstap(dnstap.Message_RESOLVER_QUERY, "dns.example.com.", dns.TypeA, 0, nil)

	out, ok := fn(dt)
	if !ok {
		t.Fatal("format func returned false")
	}
	line := strings.TrimSpace(string(out))
	if !strings.Contains(line, "RESOLVER_QUERY") {
		t.Errorf("expected RESOLVER_QUERY in output, got: %s", line)
	}
}

func TestNewStdoutFormatFunc_RcodeOnQuery(t *testing.T) {
	fn := newStdoutFormatFunc([]stdoutField{fieldName, fieldRcode})
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "example.com.", dns.TypeA, 0, nil)

	out, ok := fn(dt)
	if !ok {
		t.Fatal("format func returned false")
	}
	line := strings.TrimSpace(string(out))
	// For query, rcode should be omitted
	if line != "example.com." {
		t.Errorf("expected only name for query with rcode field, got: %s", line)
	}
}

func TestDefaultQueryFormat_NilMessage(t *testing.T) {
	dtType := dnstap.Dnstap_MESSAGE
	dt := &dnstap.Dnstap{
		Type:    &dtType,
		Message: nil,
	}
	_, ok := defaultQueryFormat(dt)
	if ok {
		t.Error("expected false for nil message")
	}
}

func TestParseOutput_Default(t *testing.T) {
	out, err := ParseOutput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output")
	}
}

func TestParseOutput_Stdout(t *testing.T) {
	out, err := ParseOutput("stdout:time,name,type")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output")
	}
}

func TestParseOutput_StdoutDefault(t *testing.T) {
	out, err := ParseOutput("stdout:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output")
	}
}

func TestParseOutput_StdoutInvalidField(t *testing.T) {
	_, err := ParseOutput("stdout:bogus")
	if err == nil {
		t.Fatal("expected error for invalid stdout field")
	}
}

func TestParseOutput_InvalidScheme(t *testing.T) {
	_, err := ParseOutput("ftp:something")
	if err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestParseOutputs_Empty(t *testing.T) {
	out, err := ParseOutputs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output for empty specs")
	}
}

func TestParseOutputs_Single(t *testing.T) {
	out, err := ParseOutputs([]string{"stdout:time,name"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output")
	}
	if _, ok := out.(*MultiOutput); ok {
		t.Fatal("single spec should not return MultiOutput")
	}
}

func TestParseOutputs_Multiple(t *testing.T) {
	out, err := ParseOutputs([]string{"stdout:time,name", "stdout:name,type"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mo, ok := out.(*MultiOutput)
	if !ok {
		t.Fatal("multiple specs should return MultiOutput")
	}
	if len(mo.outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(mo.outputs))
	}
}

func TestParseOutputs_InvalidSpec(t *testing.T) {
	_, err := ParseOutputs([]string{"stdout:bogus", "stdout:time"})
	if err == nil {
		t.Fatal("expected error for invalid spec in list")
	}
}

func TestMultiOutput_FanOut(t *testing.T) {
	// Create two stdout outputs and verify frames reach both channels
	o1, err := ParseOutput("stdout:time,name")
	if err != nil {
		t.Fatal(err)
	}
	o2, err := ParseOutput("stdout:name,type")
	if err != nil {
		t.Fatal(err)
	}

	mo := NewMultiOutput([]dnstap.Output{o1, o2})
	ch := mo.GetOutputChannel()

	// Start only the fan-out loop (not the child RunOutputLoops, to avoid stdout writes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for frame := range mo.ch {
			for _, o := range mo.outputs {
				o.GetOutputChannel() <- frame
			}
		}
	}()

	frame := []byte("test-frame")
	ch <- frame

	// Read from both child channels
	got1 := <-o1.GetOutputChannel()
	got2 := <-o2.GetOutputChannel()

	if string(got1) != "test-frame" {
		t.Errorf("output1: expected 'test-frame', got %q", got1)
	}
	if string(got2) != "test-frame" {
		t.Errorf("output2: expected 'test-frame', got %q", got2)
	}

	close(ch)
	<-done
}

func TestNewStdoutFormatFunc_ResponseTime(t *testing.T) {
	fn := newStdoutFormatFunc([]stdoutField{fieldTime, fieldName})
	// Build a response that only has ResponseTimeSec (no QueryTimeSec)
	dtType := dnstap.Dnstap_MESSAGE
	msgType := dnstap.Message_CLIENT_RESPONSE
	sec := uint64(1704067200)

	msg := &dns.Msg{}
	msg.SetQuestion("resp.example.com.", dns.TypeA)
	msg.Response = true
	packed, _ := msg.Pack()

	dt := &dnstap.Dnstap{
		Type: &dtType,
		Message: &dnstap.Message{
			Type:            &msgType,
			ResponseTimeSec: &sec,
			ResponseMessage: packed,
		},
	}

	out, ok := fn(dt)
	if !ok {
		t.Fatal("format func returned false")
	}
	line := string(out)
	if !strings.Contains(line, "2024") {
		t.Errorf("expected timestamp from ResponseTimeSec, got: %s", line)
	}
}
