package filters

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
	var msg dns.Msg
	if m.QueryAddress != nil {
		msg := new(dns.Msg)
		err := msg.Unpack(m.QueryMessage)
		if err != nil {
			return true
		}
	}

	if m.ResponseAddress != nil {
		msg := new(dns.Msg)
		err := msg.Unpack(m.ResponseMessage)
		if err != nil {
			return true
		}
	}

	questionName := msg.Question[0].Name

	return p.FQDN == questionName
}
