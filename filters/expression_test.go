package filters

import (
	"net"
	"strings"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func TestParseFilterExpression_SinglePredicate(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	if !node.Eval(msg) {
		t.Fatalf("expected node to match")
	}
}

func TestParseFilterExpression_OperatorPrecedence(t *testing.T) {
	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")

	node1, err := ParseFilterExpression("ip=1.1.1.1 or fqdn=foo.example. and rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected error for node1: %v", err)
	}
	if !node1.Eval(msg) {
		t.Fatalf("expected expression with precedence to be true")
	}

	node2, err := ParseFilterExpression("(ip=1.1.1.1 or fqdn=foo.example.) and rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected error for node2: %v", err)
	}
	if node2.Eval(msg) {
		t.Fatalf("expected parenthesized expression to be false")
	}
}

func TestParseFilterExpression_CaseInsensitiveOperators(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1 AnD (suffix=example.com. oR rcode=NOERROR)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	if !node.Eval(msg) {
		t.Fatalf("expected expression to match")
	}
}

func TestParseFilterExpression_Errors(t *testing.T) {
	cases := []string{
		"",
		"(",
		"foo=bar",
		"ip=",
		"ip=1.1.1.1 and or fqdn=a.example.",
		"ip=999.999.999.999",
		"ip=1.1.1.1 )",
	}

	for _, expr := range cases {
		_, err := ParseFilterExpression(expr)
		if err == nil {
			t.Fatalf("expected error for expression: %q", expr)
		}
		if !strings.Contains(err.Error(), "token") && !strings.Contains(err.Error(), "end of expression") {
			t.Fatalf("expected token or position hint in error for %q, got: %v", expr, err)
		}
	}
}

func TestParseFilterExpression_AllPredicates(t *testing.T) {
	queryNode, err := ParseFilterExpression("ip=1.1.1.1 and fqdn=www.example.com. and suffix=example.com.")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !queryNode.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1")) {
		t.Fatalf("expected query predicates to match")
	}

	rcodeNode, err := ParseFilterExpression("rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !rcodeNode.Eval(newResponseMessage(t, "www.example.com.", "1.1.1.1", dns.RcodeNameError)) {
		t.Fatalf("expected rcode predicate to match")
	}
}

func newQueryMessage(t *testing.T, name string, ip string) dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack query message: %v", err)
	}

	return dnstap.Message{
		QueryAddress: net.ParseIP(ip).To4(),
		QueryMessage: payload,
	}
}

func newResponseMessage(t *testing.T, name string, ip string, rcode int) dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Rcode = rcode
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response message: %v", err)
	}

	return dnstap.Message{
		ResponseAddress: net.ParseIP(ip).To4(),
		ResponseMessage: payload,
	}
}
