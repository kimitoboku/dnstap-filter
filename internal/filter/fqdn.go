package filter

import (
	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type FQDNFilter struct {
	FQDN string
}

func NewFQDNFilter(a string) *FQDNFilter {
	return &FQDNFilter{
		FQDN: a,
	}
}

func (p *FQDNFilter) Filter(m dnstap.Message) bool {
	var msgBytes []byte
	if m.QueryMessage != nil {
		msgBytes = m.QueryMessage
	} else if m.ResponseMessage != nil {
		msgBytes = m.ResponseMessage
	} else {
		return false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	questionName := msg.Question[0].Name
	return p.FQDN == questionName
}
