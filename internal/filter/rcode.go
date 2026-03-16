package filter

import (
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type RcodeFilter struct {
	Rcode string
}

func NewRcodeFilter(a string) *RcodeFilter {
	return &RcodeFilter{
		Rcode: strings.ToUpper(a),
	}
}

func (p *RcodeFilter) Filter(m dnstap.Message, ctx *EvalContext) bool {
	if m.ResponseAddress == nil {
		return false
	}

	msg := ctx.UnpackResponse(m)
	if msg == nil {
		return false
	}

	return p.Rcode == dns.RcodeToString[msg.Rcode]
}
