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
	msg := new(dns.Msg)
	if m.QueryAddress != nil {
		err := msg.Unpack(m.QueryMessage)
		if err != nil {
			return true
		}
	} else if m.ResponseAddress != nil {
		err := msg.Unpack(m.ResponseMessage)
		if err != nil {
			return true
		}
	} else {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	questionName := msg.Question[0].Name
	return p.FQDN == questionName
}
