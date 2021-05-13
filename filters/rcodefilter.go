package filters

import (
	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"strings"
)

type RcodeFilter struct {
	Rcode string
}

func NewRcodeFilter(a string) *RcodeFilter {
	return &RcodeFilter{
		Rcode: strings.ToUpper(a),
	}
}

func (p *RcodeFilter) Filter(m dnstap.Message) bool {
	if m.ResponseAddress != nil {
		msg := new(dns.Msg)
		err := msg.Unpack(m.ResponseMessage)
		if err != nil {
			return true
		}

		rcode := dns.RcodeToString[msg.Rcode]
		return p.Rcode == rcode

	} else {
		return false
	}
}
