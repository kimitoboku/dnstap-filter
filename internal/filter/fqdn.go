package filter

import (
	"github.com/dnstap/golang-dnstap"
)

type FQDNFilter struct {
	FQDN string
}

func NewFQDNFilter(a string) *FQDNFilter {
	return &FQDNFilter{
		FQDN: a,
	}
}

func (p *FQDNFilter) Filter(m *dnstap.Message, ctx *EvalContext) bool {
	msg := ctx.UnpackQueryOrResponse(m)
	if msg == nil {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	return p.FQDN == msg.Question[0].Name
}
