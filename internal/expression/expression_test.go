package expression

import (
	"net"
	"strings"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/kimitoboku/dnstap-filter/internal/filter"
	"github.com/miekg/dns"
)

func TestParseFilterExpression_SinglePredicate(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected node to match")
	}
}

func TestParseFilterExpression_OperatorPrecedence(t *testing.T) {
	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")

	node1, err := ParseFilterExpression("ip=1.1.1.1 or fqdn=foo.example. and rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected error for node1: %v", err)
	}
	if !node1.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected expression with precedence to be true")
	}

	node2, err := ParseFilterExpression("(ip=1.1.1.1 or fqdn=foo.example.) and rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected error for node2: %v", err)
	}
	if node2.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected parenthesized expression to be false")
	}
}

func TestParseFilterExpression_CaseInsensitiveOperators(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1 AnD (suffix=example.com. oR rcode=NOERROR)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected expression to match")
	}
}

func TestParseFilterExpression_EmptyMatchesAll(t *testing.T) {
	node, err := ParseFilterExpression("")
	if err != nil {
		t.Fatalf("unexpected error for empty expression: %v", err)
	}
	msg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected empty expression to match all messages")
	}
}

func TestParseFilterExpression_Errors(t *testing.T) {
	cases := []string{
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
	if !queryNode.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected query predicates to match")
	}

	rcodeNode, err := ParseFilterExpression("rcode=NXDOMAIN")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !rcodeNode.Eval(newResponseMessage(t, "www.example.com.", "1.1.1.1", dns.RcodeNameError), filter.NewEvalContext()) {
		t.Fatalf("expected rcode predicate to match")
	}
}

func TestFormatTree(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1 and (suffix=example.com. or rcode=NXDOMAIN)")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	got := filter.FormatTree(node)
	wantContains := []string{
		"AND",
		"PREDICATE ip=1.1.1.1",
		"OR",
		"PREDICATE suffix=example.com.",
		"PREDICATE rcode=NXDOMAIN",
	}
	for _, w := range wantContains {
		if !strings.Contains(got, w) {
			t.Fatalf("expected tree to contain %q, got:\n%s", w, got)
		}
	}
}

func TestParseFilterExpression_SuffixOrDoesNotMatchInvalidDNSPayload(t *testing.T) {
	node, err := ParseFilterExpression("suffix=nhncorp.com. or suffix=nfra.io. or suffix=dev.ui.naver.com.")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	msg := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryMessage: nil,
	}
	if node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected false for invalid DNS payload, got true")
	}
}

func TestIPFilter_MatchesBothAddresses(t *testing.T) {
	node, err := ParseFilterExpression("ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected ip filter to match QueryAddress")
	}

	// ip= now matches both QueryAddress and ResponseAddress
	if !node.Eval(newResponseMessage(t, "www.example.com.", "1.1.1.1", dns.RcodeSuccess), filter.NewEvalContext()) {
		t.Fatalf("expected ip filter to match ResponseAddress")
	}
}

func TestIPFilter_SrcDst(t *testing.T) {
	srcNode, err := ParseFilterExpression("src.ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dstNode, err := ParseFilterExpression("dst.ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	queryMsg := newQueryMessage(t, "www.example.com.", "1.1.1.1")
	responseMsg := newResponseMessage(t, "www.example.com.", "1.1.1.1", dns.RcodeSuccess)

	// src.ip matches QueryAddress only
	if !srcNode.Eval(queryMsg, filter.NewEvalContext()) {
		t.Fatalf("expected src.ip to match QueryAddress")
	}
	if srcNode.Eval(responseMsg, filter.NewEvalContext()) {
		t.Fatalf("expected src.ip to NOT match ResponseAddress-only message")
	}

	// dst.ip matches ResponseAddress only
	if dstNode.Eval(queryMsg, filter.NewEvalContext()) {
		t.Fatalf("expected dst.ip to NOT match QueryAddress-only message")
	}
	if !dstNode.Eval(responseMsg, filter.NewEvalContext()) {
		t.Fatalf("expected dst.ip to match ResponseAddress")
	}
}

func TestSubnetFilter_Match(t *testing.T) {
	node, err := ParseFilterExpression("subnet=192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !node.Eval(newQueryMessage(t, "www.example.com.", "192.168.1.42"), filter.NewEvalContext()) {
		t.Fatalf("expected subnet filter to match IP inside range")
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "192.168.2.1"), filter.NewEvalContext()) {
		t.Fatalf("expected subnet filter to not match IP outside range")
	}

	// subnet= now matches ResponseAddress too
	responseMsg := newResponseMessage(t, "www.example.com.", "192.168.1.42", dns.RcodeSuccess)
	if !node.Eval(responseMsg, filter.NewEvalContext()) {
		t.Fatalf("expected subnet filter to match ResponseAddress inside range")
	}
}

func TestSubnetFilter_SrcDst(t *testing.T) {
	srcNode, err := ParseFilterExpression("src.subnet=10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dstNode, err := ParseFilterExpression("dst.subnet=10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	queryMsg := newQueryMessage(t, "www.example.com.", "10.1.2.3")
	responseMsg := newResponseMessage(t, "www.example.com.", "10.1.2.3", dns.RcodeSuccess)

	if !srcNode.Eval(queryMsg, filter.NewEvalContext()) {
		t.Fatalf("expected src.subnet to match QueryAddress")
	}
	if srcNode.Eval(responseMsg, filter.NewEvalContext()) {
		t.Fatalf("expected src.subnet to NOT match ResponseAddress-only message")
	}

	if dstNode.Eval(queryMsg, filter.NewEvalContext()) {
		t.Fatalf("expected dst.subnet to NOT match QueryAddress-only message")
	}
	if !dstNode.Eval(responseMsg, filter.NewEvalContext()) {
		t.Fatalf("expected dst.subnet to match ResponseAddress")
	}
}

func TestSubnetFilter_InvalidCIDR(t *testing.T) {
	_, err := ParseFilterExpression("subnet=not-a-cidr")
	if err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}

func TestPortFilter_Match(t *testing.T) {
	node, err := ParseFilterExpression("port=53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	qport := uint32(12345)
	rport := uint32(53)
	msg := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryPort:    &qport,
		ResponsePort: &rport,
		QueryMessage: packTestQuery(t, "www.example.com.", dns.TypeA),
	}
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected port=53 to match ResponsePort")
	}

	qport2 := uint32(53)
	msg2 := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryPort:    &qport2,
		QueryMessage: packTestQuery(t, "www.example.com.", dns.TypeA),
	}
	if !node.Eval(msg2, filter.NewEvalContext()) {
		t.Fatalf("expected port=53 to match QueryPort")
	}

	qport3 := uint32(12345)
	rport3 := uint32(8080)
	msg3 := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryPort:    &qport3,
		ResponsePort: &rport3,
		QueryMessage: packTestQuery(t, "www.example.com.", dns.TypeA),
	}
	if node.Eval(msg3, filter.NewEvalContext()) {
		t.Fatalf("expected port=53 to NOT match when neither port is 53")
	}
}

func TestPortFilter_SrcDst(t *testing.T) {
	srcNode, err := ParseFilterExpression("src.port=12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dstNode, err := ParseFilterExpression("dst.port=53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	qport := uint32(12345)
	rport := uint32(53)
	msg := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryPort:    &qport,
		ResponsePort: &rport,
		QueryMessage: packTestQuery(t, "www.example.com.", dns.TypeA),
	}

	if !srcNode.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected src.port=12345 to match QueryPort")
	}
	if !dstNode.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected dst.port=53 to match ResponsePort")
	}

	// src.port should NOT match ResponsePort
	srcNode2, _ := ParseFilterExpression("src.port=53")
	if srcNode2.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected src.port=53 to NOT match when QueryPort is 12345")
	}
}

func TestPortFilter_Invalid(t *testing.T) {
	_, err := ParseFilterExpression("port=notanumber")
	if err == nil {
		t.Fatalf("expected error for invalid port")
	}

	_, err = ParseFilterExpression("port=99999")
	if err == nil {
		t.Fatalf("expected error for port out of range")
	}
}

func TestQtypeFilter_Match(t *testing.T) {
	node, err := ParseFilterExpression("qtype=AAAA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("www.example.com.", dns.TypeAAAA)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	dnstapMsg := &dnstap.Message{
		QueryAddress: net.ParseIP("1.1.1.1").To4(),
		QueryMessage: payload,
	}

	if !node.Eval(dnstapMsg, filter.NewEvalContext()) {
		t.Fatalf("expected qtype=AAAA to match AAAA query")
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected qtype=AAAA to not match A query")
	}
}

func TestQtypeFilter_CaseInsensitive(t *testing.T) {
	_, err := ParseFilterExpression("qtype=aaaa")
	if err != nil {
		t.Fatalf("expected case-insensitive qtype to be accepted: %v", err)
	}
}

func TestQtypeFilter_Invalid(t *testing.T) {
	_, err := ParseFilterExpression("qtype=NOTATYPE")
	if err == nil {
		t.Fatalf("expected error for unknown DNS type")
	}
}

func TestRdataFilter_IPMatch(t *testing.T) {
	node, err := ParseFilterExpression("rdata=93.184.216.34")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aRR, _ := dns.NewRR("www.example.com. 300 IN A 93.184.216.34")
	msg := newResponseMessageWithAnswers(t, "www.example.com.", "1.1.1.1", []dns.RR{aRR})
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected rdata IP filter to match A record")
	}

	aRR2, _ := dns.NewRR("www.example.com. 300 IN A 1.2.3.4")
	msg2 := newResponseMessageWithAnswers(t, "www.example.com.", "1.1.1.1", []dns.RR{aRR2})
	if node.Eval(msg2, filter.NewEvalContext()) {
		t.Fatalf("expected rdata IP filter to not match different A record")
	}
}

func TestRdataFilter_SubnetMatch(t *testing.T) {
	node, err := ParseFilterExpression("rdata=10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aRR, _ := dns.NewRR("host.example.com. 300 IN A 10.42.1.5")
	msg := newResponseMessageWithAnswers(t, "host.example.com.", "1.1.1.1", []dns.RR{aRR})
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected rdata subnet filter to match A record in range")
	}

	aRR2, _ := dns.NewRR("host.example.com. 300 IN A 192.168.1.1")
	msg2 := newResponseMessageWithAnswers(t, "host.example.com.", "1.1.1.1", []dns.RR{aRR2})
	if node.Eval(msg2, filter.NewEvalContext()) {
		t.Fatalf("expected rdata subnet filter to not match A record outside range")
	}
}

func TestRdataFilter_TXTMatch(t *testing.T) {
	node, err := ParseFilterExpression("rdata=v=spf1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	txtRR, _ := dns.NewRR(`example.com. 300 IN TXT "v=spf1 include:example.net ~all"`)
	msg := newResponseMessageWithAnswers(t, "example.com.", "1.1.1.1", []dns.RR{txtRR})
	if !node.Eval(msg, filter.NewEvalContext()) {
		t.Fatalf("expected rdata TXT filter to match substring")
	}
}

func TestRdataFilter_NoMatchOnQueryMessage(t *testing.T) {
	node, err := ParseFilterExpression("rdata=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("rdata filter must not match query messages")
	}
}

func TestRdataFilter_InvalidCIDR(t *testing.T) {
	_, err := ParseFilterExpression("rdata=192.168/bad")
	if err == nil {
		t.Fatalf("expected error for invalid CIDR in rdata")
	}
}

func TestMsgtypeFilter_Match(t *testing.T) {
	node, err := ParseFilterExpression("msgtype=CLIENT_QUERY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clientQuery := newTypedMessage(t, "www.example.com.", "1.1.1.1", dns.TypeA, dnstap.Message_CLIENT_QUERY)
	if !node.Eval(clientQuery, filter.NewEvalContext()) {
		t.Fatalf("expected msgtype=CLIENT_QUERY to match CLIENT_QUERY message")
	}

	clientResponse := newTypedMessage(t, "www.example.com.", "1.1.1.1", dns.TypeA, dnstap.Message_CLIENT_RESPONSE)
	if node.Eval(clientResponse, filter.NewEvalContext()) {
		t.Fatalf("expected msgtype=CLIENT_QUERY to not match CLIENT_RESPONSE")
	}
}

func TestMsgtypeFilter_CaseInsensitive(t *testing.T) {
	_, err := ParseFilterExpression("msgtype=client_query")
	if err != nil {
		t.Fatalf("expected case-insensitive msgtype to be accepted: %v", err)
	}
}

func TestMsgtypeFilter_Invalid(t *testing.T) {
	_, err := ParseFilterExpression("msgtype=NOT_A_TYPE")
	if err == nil {
		t.Fatalf("expected error for unknown msgtype")
	}
}

func TestRegexpFilter_Match(t *testing.T) {
	node, err := ParseFilterExpression(`regexp=^www\.example\.com\.$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected regexp to match www.example.com.")
	}

	if node.Eval(newQueryMessage(t, "mail.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected regexp to not match mail.example.com.")
	}
}

func TestRegexpFilter_PartialMatch(t *testing.T) {
	node, err := ParseFilterExpression(`regexp=\.example\.com\.$`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected regexp to match www.example.com.")
	}

	if !node.Eval(newQueryMessage(t, "mail.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected regexp to match mail.example.com.")
	}

	if node.Eval(newQueryMessage(t, "www.example.org.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected regexp to not match www.example.org.")
	}
}

func TestRegexpFilter_InvalidRegexp(t *testing.T) {
	_, err := ParseFilterExpression(`regexp=[invalid`)
	if err == nil {
		t.Fatalf("expected error for invalid regexp")
	}
}

func TestNotOperator_Simple(t *testing.T) {
	node, err := ParseFilterExpression("not ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected not ip=1.1.1.1 to NOT match 1.1.1.1")
	}
	if !node.Eval(newQueryMessage(t, "www.example.com.", "2.2.2.2"), filter.NewEvalContext()) {
		t.Fatalf("expected not ip=1.1.1.1 to match 2.2.2.2")
	}
}

func TestNotOperator_WithGroup(t *testing.T) {
	node, err := ParseFilterExpression("not (ip=1.1.1.1 or ip=2.2.2.2)")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected not (ip=1.1.1.1 or ip=2.2.2.2) to NOT match 1.1.1.1")
	}
	if node.Eval(newQueryMessage(t, "www.example.com.", "2.2.2.2"), filter.NewEvalContext()) {
		t.Fatalf("expected not (ip=1.1.1.1 or ip=2.2.2.2) to NOT match 2.2.2.2")
	}
	if !node.Eval(newQueryMessage(t, "www.example.com.", "3.3.3.3"), filter.NewEvalContext()) {
		t.Fatalf("expected not (ip=1.1.1.1 or ip=2.2.2.2) to match 3.3.3.3")
	}
}

func TestNotOperator_CombinedWithAnd(t *testing.T) {
	node, err := ParseFilterExpression("suffix=example.com. and not ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected to NOT match when ip=1.1.1.1")
	}
	if !node.Eval(newQueryMessage(t, "www.example.com.", "2.2.2.2"), filter.NewEvalContext()) {
		t.Fatalf("expected to match when ip=2.2.2.2 and suffix matches")
	}
}

func TestNotOperator_DoubleNegation(t *testing.T) {
	node, err := ParseFilterExpression("not not ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected not not ip=1.1.1.1 to match 1.1.1.1")
	}
	if node.Eval(newQueryMessage(t, "www.example.com.", "2.2.2.2"), filter.NewEvalContext()) {
		t.Fatalf("expected not not ip=1.1.1.1 to NOT match 2.2.2.2")
	}
}

func TestNotOperator_CaseInsensitive(t *testing.T) {
	node, err := ParseFilterExpression("NOT ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Eval(newQueryMessage(t, "www.example.com.", "1.1.1.1"), filter.NewEvalContext()) {
		t.Fatalf("expected NOT to work case-insensitively")
	}
}

func TestNotOperator_Errors(t *testing.T) {
	cases := []string{
		"not",
		"not and ip=1.1.1.1",
		"not or ip=1.1.1.1",
	}

	for _, expr := range cases {
		_, err := ParseFilterExpression(expr)
		if err == nil {
			t.Fatalf("expected error for expression: %q", expr)
		}
	}
}

func TestFormatTree_WithNot(t *testing.T) {
	node, err := ParseFilterExpression("not ip=1.1.1.1")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	got := filter.FormatTree(node)
	if !strings.Contains(got, "NOT") {
		t.Fatalf("expected tree to contain NOT, got:\n%s", got)
	}
	if !strings.Contains(got, "PREDICATE ip=1.1.1.1") {
		t.Fatalf("expected tree to contain PREDICATE ip=1.1.1.1, got:\n%s", got)
	}
}

func newResponseMessageWithAnswers(t *testing.T, name string, ip string, answers []dns.RR) *dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = answers
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response message: %v", err)
	}

	msgType := dnstap.Message_CLIENT_RESPONSE
	return &dnstap.Message{
		Type:            &msgType,
		ResponseAddress: net.ParseIP(ip).To4(),
		ResponseMessage: payload,
	}
}

func newTypedMessage(t *testing.T, name string, ip string, qtype uint16, msgType dnstap.Message_Type) *dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}

	return &dnstap.Message{
		Type:         &msgType,
		QueryAddress: net.ParseIP(ip).To4(),
		QueryMessage: payload,
	}
}

func newQueryMessage(t *testing.T, name string, ip string) *dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack query message: %v", err)
	}

	return &dnstap.Message{
		QueryAddress: net.ParseIP(ip).To4(),
		QueryMessage: payload,
	}
}

func packTestQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	return payload
}

func newResponseMessage(t *testing.T, name string, ip string, rcode int) *dnstap.Message {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Rcode = rcode
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack response message: %v", err)
	}

	return &dnstap.Message{
		ResponseAddress: net.ParseIP(ip).To4(),
		ResponseMessage: payload,
	}
}
