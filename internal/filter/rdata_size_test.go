package filter

import (
	"net"
	"testing"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func TestRdataSizeFilter_Match(t *testing.T) {
	f, err := NewRdataSizeFilter("2")
	if err != nil {
		t.Fatal(err)
	}

	answers := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("1.1.1.1"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("2.2.2.2"),
		},
	}
	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, answers)
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for 2 answer records with rdata.size=2")
	}
}

func TestRdataSizeFilter_NoMatch(t *testing.T) {
	f, err := NewRdataSizeFilter("3")
	if err != nil {
		t.Fatal(err)
	}

	answers := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("1.1.1.1"),
		},
	}
	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, answers)
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected no match for 1 answer record with rdata.size=3")
	}
}

func TestRdataSizeFilter_ZeroAnswers(t *testing.T) {
	f, err := NewRdataSizeFilter("0")
	if err != nil {
		t.Fatal(err)
	}

	msg := makeResponseMessage(t, "example.com.", "1.1.1.1", dns.RcodeSuccess, nil)
	ctx := NewEvalContext()
	if !f.Filter(msg, ctx) {
		t.Fatal("expected match for 0 answer records with rdata.size=0")
	}
}

func TestRdataSizeFilter_NilResponseMessage(t *testing.T) {
	f, _ := NewRdataSizeFilter("1")
	msg := &dnstap.Message{ResponseMessage: nil}
	ctx := NewEvalContext()
	if f.Filter(msg, ctx) {
		t.Fatal("expected false for nil ResponseMessage")
	}
}

func TestRdataSizeFilter_InvalidValue(t *testing.T) {
	_, err := NewRdataSizeFilter("abc")
	if err == nil {
		t.Fatal("expected error for non-integer value")
	}
}

func TestRdataSizeFilter_NegativeValue(t *testing.T) {
	_, err := NewRdataSizeFilter("-1")
	if err == nil {
		t.Fatal("expected error for negative value")
	}
}
