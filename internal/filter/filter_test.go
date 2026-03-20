package filter

import (
	"net"
	"strings"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func packQuery(t testing.TB, name string, qtype uint16) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	return payload
}

func makeQueryMessage(t testing.TB, name string, ip string) *dnstap.Message {
	t.Helper()
	return &dnstap.Message{
		QueryAddress: net.ParseIP(ip).To4(),
		QueryMessage: packQuery(t, name, dns.TypeA),
	}
}

// TestOptimizeTree_ReordersAnd verifies that AND nodes with a cheap right child
// get reordered so the cheap child is evaluated first.
func TestOptimizeTree_ReordersAnd(t *testing.T) {
	// suffix (expensive, cost=10) AND ip (cheap, cost=1)
	tree := &AndNode{
		Left:  &PredicateNode{Key: "suffix", Value: "example.com."},
		Right: &PredicateNode{Key: "ip", Value: "1.1.1.1"},
	}
	opt := OptimizeTree(tree)
	and, ok := opt.(*AndNode)
	if !ok {
		t.Fatalf("expected *AndNode, got %T", opt)
	}
	left, ok := and.Left.(*PredicateNode)
	if !ok || left.Key != "ip" {
		t.Fatalf("expected ip on left after optimization, got %s", left.Key)
	}
}

// TestOptimizeTree_NoReorderWhenAlreadyOptimal verifies no swap when left is
// already cheaper.
func TestOptimizeTree_NoReorderWhenAlreadyOptimal(t *testing.T) {
	tree := &AndNode{
		Left:  &PredicateNode{Key: "ip", Value: "1.1.1.1"},
		Right: &PredicateNode{Key: "suffix", Value: "example.com."},
	}
	opt := OptimizeTree(tree)
	and := opt.(*AndNode)
	left := and.Left.(*PredicateNode)
	if left.Key != "ip" {
		t.Fatalf("expected ip to stay on left, got %s", left.Key)
	}
}

// TestOptimizeTree_ReordersOr verifies OR nodes also reorder.
func TestOptimizeTree_ReordersOr(t *testing.T) {
	tree := &OrNode{
		Left:  &PredicateNode{Key: "fqdn", Value: "example.com."},
		Right: &PredicateNode{Key: "msgtype", Value: "CLIENT_QUERY"},
	}
	opt := OptimizeTree(tree)
	or := opt.(*OrNode)
	left := or.Left.(*PredicateNode)
	if left.Key != "msgtype" {
		t.Fatalf("expected msgtype on left after optimization, got %s", left.Key)
	}
}

// TestEvalContext_CachesUnpack verifies that multiple filters sharing a context
// produce correct results (the cache doesn't break correctness).
func TestEvalContext_CachesUnpack(t *testing.T) {
	msg := makeQueryMessage(t, "www.example.com.", "1.1.1.1")
	ctx := NewEvalContext()

	fqdn := NewFQDNFilter("www.example.com.")
	suffix := NewSuffixFilter("example.com.")
	qtype := NewQtypeFilter("A")

	if !fqdn.Filter(msg, ctx) {
		t.Fatal("fqdn filter should match")
	}
	if !suffix.Filter(msg, ctx) {
		t.Fatal("suffix filter should match (using cached unpack)")
	}
	if !qtype.Filter(msg, ctx) {
		t.Fatal("qtype filter should match (using cached unpack)")
	}
}

// TestEvalContext_Reset verifies that Reset clears the cache.
func TestEvalContext_Reset(t *testing.T) {
	msg1 := makeQueryMessage(t, "www.example.com.", "1.1.1.1")
	msg2 := makeQueryMessage(t, "other.example.org.", "2.2.2.2")

	ctx := NewEvalContext()
	fqdn := NewFQDNFilter("www.example.com.")

	if !fqdn.Filter(msg1, ctx) {
		t.Fatal("should match msg1")
	}

	ctx.Reset()

	if fqdn.Filter(msg2, ctx) {
		t.Fatal("should not match msg2 after reset")
	}
}

// TestOptimizeTree_ResultsUnchanged verifies that OptimizeTree does not change
// the evaluation result for various filter trees and messages.
func TestOptimizeTree_ResultsUnchanged(t *testing.T) {
	msgType := dnstap.Message_CLIENT_RESPONSE

	messages := []struct {
		name string
		msg  *dnstap.Message
	}{
		{
			"query matching ip and suffix",
			makeQueryMessage(t, "www.example.com.", "1.1.1.1"),
		},
		{
			"query non-matching ip",
			makeQueryMessage(t, "www.example.com.", "9.9.9.9"),
		},
		{
			"query different domain",
			makeQueryMessage(t, "other.example.org.", "1.1.1.1"),
		},
		{
			"response message",
			&dnstap.Message{
				Type:            &msgType,
				ResponseAddress: net.ParseIP("1.1.1.1").To4(),
				ResponseMessage: packQuery(t, "www.example.com.", dns.TypeA),
			},
		},
		{
			"nil query message",
			&dnstap.Message{
				QueryAddress: net.ParseIP("1.1.1.1").To4(),
				QueryMessage: nil,
			},
		},
	}

	trees := []struct {
		name string
		tree Node
	}{
		{
			"suffix AND ip",
			&AndNode{
				Left:  &PredicateNode{Filter: NewSuffixFilter("example.com."), Key: "suffix", Value: "example.com."},
				Right: &PredicateNode{Filter: NewIPFilter("1.1.1.1"), Key: "ip", Value: "1.1.1.1"},
			},
		},
		{
			"fqdn OR ip",
			&OrNode{
				Left:  &PredicateNode{Filter: NewFQDNFilter("www.example.com."), Key: "fqdn", Value: "www.example.com."},
				Right: &PredicateNode{Filter: NewIPFilter("9.9.9.9"), Key: "ip", Value: "9.9.9.9"},
			},
		},
		{
			"(suffix AND qtype) OR ip",
			&OrNode{
				Left: &AndNode{
					Left:  &PredicateNode{Filter: NewSuffixFilter("example.com."), Key: "suffix", Value: "example.com."},
					Right: &PredicateNode{Filter: NewQtypeFilter("A"), Key: "qtype", Value: "A"},
				},
				Right: &PredicateNode{Filter: NewIPFilter("9.9.9.9"), Key: "ip", Value: "9.9.9.9"},
			},
		},
		{
			"NOT suffix AND ip",
			&AndNode{
				Left:  &NotNode{Child: &PredicateNode{Filter: NewSuffixFilter("example.org."), Key: "suffix", Value: "example.org."}},
				Right: &PredicateNode{Filter: NewIPFilter("1.1.1.1"), Key: "ip", Value: "1.1.1.1"},
			},
		},
		{
			"ip AND suffix AND qtype (deep)",
			&AndNode{
				Left: &PredicateNode{Filter: NewSuffixFilter("example.com."), Key: "suffix", Value: "example.com."},
				Right: &AndNode{
					Left:  &PredicateNode{Filter: NewQtypeFilter("A"), Key: "qtype", Value: "A"},
					Right: &PredicateNode{Filter: NewIPFilter("1.1.1.1"), Key: "ip", Value: "1.1.1.1"},
				},
			},
		},
		{
			"msgtype AND fqdn",
			&AndNode{
				Left:  &PredicateNode{Filter: NewFQDNFilter("www.example.com."), Key: "fqdn", Value: "www.example.com."},
				Right: &PredicateNode{Filter: NewMsgTypeFilter("CLIENT_RESPONSE"), Key: "msgtype", Value: "CLIENT_RESPONSE"},
			},
		},
	}

	for _, tc := range trees {
		optimized := OptimizeTree(tc.tree)
		for _, mc := range messages {
			t.Run(tc.name+"/"+mc.name, func(t *testing.T) {
				ctxOrig := NewEvalContext()
				ctxOpt := NewEvalContext()

				want := tc.tree.Eval(mc.msg, ctxOrig)
				got := optimized.Eval(mc.msg, ctxOpt)

				if got != want {
					t.Fatalf("OptimizeTree changed result: original=%v optimized=%v", want, got)
				}
			})
		}
	}
}

// BenchmarkEval_SingleFilter benchmarks a single filter evaluation.
func BenchmarkEval_SingleFilter(b *testing.B) {
	msg := makeQueryMessage(b, "www.example.com.", "1.1.1.1")
	node := &PredicateNode{
		Filter: NewFQDNFilter("www.example.com."),
		Key:    "fqdn",
		Value:  "www.example.com.",
	}
	ctx := NewEvalContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Reset()
		node.Eval(msg, ctx)
	}
}

// BenchmarkEval_MultipleFiltersWithContext benchmarks multiple filters sharing
// a context (DNS unpack is cached).
func BenchmarkEval_MultipleFiltersWithContext(b *testing.B) {
	msg := makeQueryMessage(b, "www.example.com.", "1.1.1.1")
	node := &AndNode{
		Left: &PredicateNode{
			Filter: NewFQDNFilter("www.example.com."),
			Key:    "fqdn",
			Value:  "www.example.com.",
		},
		Right: &AndNode{
			Left: &PredicateNode{
				Filter: NewSuffixFilter("example.com."),
				Key:    "suffix",
				Value:  "example.com.",
			},
			Right: &PredicateNode{
				Filter: NewQtypeFilter("A"),
				Key:    "qtype",
				Value:  "A",
			},
		},
	}
	ctx := NewEvalContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Reset()
		node.Eval(msg, ctx)
	}
}

// --- Helper: build a response dnstap message ---

func packResponse(t testing.TB, name string, qtype uint16, rcode int, answers []dns.RR) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.Rcode = rcode
	msg.Response = true
	msg.Answer = answers
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response: %v", err)
	}
	return payload
}

func makeResponseMessage(t testing.TB, name string, ip string, rcode int, answers []dns.RR) *dnstap.Message {
	t.Helper()
	return &dnstap.Message{
		ResponseAddress: net.ParseIP(ip).To4(),
		ResponseMessage: packResponse(t, name, dns.TypeA, rcode, answers),
	}
}

// --- SubnetFilter tests ---

func TestSubnetFilter(t *testing.T) {
	f := NewSubnetFilter("192.168.1.0/24")

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"match", "192.168.1.100", true},
		{"no match", "10.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := makeQueryMessage(t, "example.com.", tt.ip)
			ctx := NewEvalContext()
			if got := f.Filter(msg, ctx); got != tt.want {
				t.Fatalf("SubnetFilter(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestSubnetFilter_NilQueryAddress(t *testing.T) {
	f := NewSubnetFilter("10.0.0.0/8")
	msg := &dnstap.Message{QueryAddress: nil}
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected false for nil QueryAddress")
	}
}

func TestSubnetFilter_InvalidCIDR(t *testing.T) {
	f := NewSubnetFilter("not-a-cidr")
	if f.Net != nil {
		t.Fatal("expected nil Net for invalid CIDR")
	}
}

// --- RegexpFilter tests ---

func TestRegexpFilter(t *testing.T) {
	f, err := NewRegexpFilter(`^www\..*\.com\.$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		qname  string
		want   bool
	}{
		{"match", "www.example.com.", true},
		{"no match", "mail.example.com.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := makeQueryMessage(t, tt.qname, "1.1.1.1")
			ctx := NewEvalContext()
			if got := f.Filter(msg, ctx); got != tt.want {
				t.Fatalf("RegexpFilter(%s) = %v, want %v", tt.qname, got, tt.want)
			}
		})
	}
}

func TestRegexpFilter_InvalidPattern(t *testing.T) {
	_, err := NewRegexpFilter("[invalid")
	if err == nil {
		t.Fatal("expected error for invalid regexp")
	}
}

func TestRegexpFilter_NilMessage(t *testing.T) {
	f, _ := NewRegexpFilter(".*")
	msg := &dnstap.Message{}
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected false for nil query/response message")
	}
}

// --- RcodeFilter tests ---

func TestRcodeFilter(t *testing.T) {
	tests := []struct {
		name  string
		rcode string
		msgRC int
		want  bool
	}{
		{"match NOERROR", "NOERROR", dns.RcodeSuccess, true},
		{"match NXDOMAIN", "NXDOMAIN", dns.RcodeNameError, true},
		{"no match", "SERVFAIL", dns.RcodeSuccess, false},
		{"case insensitive", "noerror", dns.RcodeSuccess, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewRcodeFilter(tt.rcode)
			msg := makeResponseMessage(t, "example.com.", "1.1.1.1", tt.msgRC, nil)
			ctx := NewEvalContext()
			if got := f.Filter(msg, ctx); got != tt.want {
				t.Fatalf("RcodeFilter(%s) = %v, want %v", tt.rcode, got, tt.want)
			}
		})
	}
}

func TestRcodeFilter_NilResponseAddress(t *testing.T) {
	f := NewRcodeFilter("NOERROR")
	msg := &dnstap.Message{ResponseAddress: nil}
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected false for nil ResponseAddress")
	}
}

// --- RdataFilter tests ---

func TestRdataFilter_IP(t *testing.T) {
	f, err := NewRdataFilter("93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}

	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP("93.184.216.34"),
	}

	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, []dns.RR{aRecord})
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for IP rdata filter")
	}

	// Non-matching IP
	f2, _ := NewRdataFilter("1.2.3.4")
	ctx.Reset()
	if f2.Filter(msg, ctx) {
		t.Fatal("expected no match for different IP")
	}
}

func TestRdataFilter_Subnet(t *testing.T) {
	f, err := NewRdataFilter("93.184.216.0/24")
	if err != nil {
		t.Fatal(err)
	}

	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP("93.184.216.34"),
	}
	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, []dns.RR{aRecord})
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for subnet rdata filter")
	}
}

func TestRdataFilter_TXT(t *testing.T) {
	f, err := NewRdataFilter("v=spf1")
	if err != nil {
		t.Fatal(err)
	}

	txtRecord := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"v=spf1 include:example.com ~all"},
	}
	msg := &dnstap.Message{
		ResponseMessage: packResponse(t, "example.com.", dns.TypeTXT, dns.RcodeSuccess, []dns.RR{txtRecord}),
	}
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for TXT rdata filter")
	}
}

func TestRdataFilter_NilResponseMessage(t *testing.T) {
	f, _ := NewRdataFilter("1.2.3.4")
	msg := &dnstap.Message{ResponseMessage: nil}
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected false for nil ResponseMessage")
	}
}

func TestRdataFilter_InvalidCIDR(t *testing.T) {
	_, err := NewRdataFilter("1.2.3/bad")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestRdataFilter_AAAA(t *testing.T) {
	f, err := NewRdataFilter("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}

	aaaaRecord := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, []dns.RR{aaaaRecord})
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for AAAA rdata filter")
	}
}

// --- FormatTree tests ---

func TestFormatTree(t *testing.T) {
	tree := &AndNode{
		Left:  &PredicateNode{Key: "ip", Value: "1.1.1.1"},
		Right: &OrNode{
			Left:  &PredicateNode{Key: "fqdn", Value: "example.com."},
			Right: &NotNode{Child: &PredicateNode{Key: "suffix", Value: "test."}},
		},
	}
	out := FormatTree(tree)
	if !strings.Contains(out, "AND") {
		t.Fatal("expected AND in output")
	}
	if !strings.Contains(out, "OR") {
		t.Fatal("expected OR in output")
	}
	if !strings.Contains(out, "NOT") {
		t.Fatal("expected NOT in output")
	}
	if !strings.Contains(out, "PREDICATE ip=1.1.1.1") {
		t.Fatal("expected PREDICATE ip=1.1.1.1 in output")
	}
}

func TestFormatTree_MatchAll(t *testing.T) {
	out := FormatTree(&MatchAllNode{})
	if out != "MATCH_ALL" {
		t.Fatalf("expected MATCH_ALL, got %q", out)
	}
}

func TestFormatTree_Nil(t *testing.T) {
	out := FormatTree(nil)
	if !strings.Contains(out, "<nil>") {
		t.Fatalf("expected <nil>, got %q", out)
	}
}

// --- Node Eval edge case tests ---

func TestMatchAllNode_Eval(t *testing.T) {
	n := &MatchAllNode{}
	if !n.Eval(nil, nil) {
		t.Fatal("MatchAllNode should always return true")
	}
}

func TestPredicateNode_NilFilter(t *testing.T) {
	n := &PredicateNode{Filter: nil}
	ctx := NewEvalContext()
	if n.Eval(&dnstap.Message{}, ctx) {
		t.Fatal("expected false for nil filter")
	}
}

func TestAndNode_NilChildren(t *testing.T) {
	n := &AndNode{Left: nil, Right: &MatchAllNode{}}
	ctx := NewEvalContext()
	if n.Eval(&dnstap.Message{}, ctx) {
		t.Fatal("expected false for nil left child")
	}
}

func TestOrNode_NilChildren(t *testing.T) {
	n := &OrNode{Left: nil, Right: nil}
	ctx := NewEvalContext()
	if n.Eval(&dnstap.Message{}, ctx) {
		t.Fatal("expected false for nil children")
	}
}

func TestNotNode_NilChild(t *testing.T) {
	n := &NotNode{Child: nil}
	ctx := NewEvalContext()
	if n.Eval(&dnstap.Message{}, ctx) {
		t.Fatal("expected false for nil child")
	}
}

// BenchmarkEval_MixedCheapExpensive benchmarks a mix of cheap and expensive
// filters with optimization.
func BenchmarkEval_MixedCheapExpensive(b *testing.B) {
	msg := makeQueryMessage(b, "www.example.com.", "1.1.1.1")
	tree := &AndNode{
		Left: &PredicateNode{
			Filter: NewSuffixFilter("example.com."),
			Key:    "suffix",
			Value:  "example.com.",
		},
		Right: &PredicateNode{
			Filter: NewIPFilter("1.1.1.1"),
			Key:    "ip",
			Value:  "1.1.1.1",
		},
	}
	optimized := OptimizeTree(tree)
	ctx := NewEvalContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Reset()
		optimized.Eval(msg, ctx)
	}
}

// BenchmarkEval_MixedCheapExpensive_ShortCircuit benchmarks short-circuit with
// a cheap filter that fails, avoiding expensive DNS unpack.
func BenchmarkEval_MixedCheapExpensive_ShortCircuit(b *testing.B) {
	msg := makeQueryMessage(b, "www.example.com.", "1.1.1.1")
	tree := &AndNode{
		Left: &PredicateNode{
			Filter: NewSuffixFilter("example.com."),
			Key:    "suffix",
			Value:  "example.com.",
		},
		Right: &PredicateNode{
			Filter: NewIPFilter("2.2.2.2"), // won't match -> short-circuit
			Key:    "ip",
			Value:  "2.2.2.2",
		},
	}
	optimized := OptimizeTree(tree)
	ctx := NewEvalContext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Reset()
		optimized.Eval(msg, ctx)
	}
}
