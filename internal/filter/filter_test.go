package filter

import (
	"net"
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

func makeQueryMessage(t testing.TB, name string, ip string) dnstap.Message {
	t.Helper()
	return dnstap.Message{
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
