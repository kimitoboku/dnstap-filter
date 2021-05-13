package filters

import (
	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"strings"
)

type SuffixFilter struct {
	Suffix string
}

func NewSuffixFilter(a string) *SuffixFilter {
	return &SuffixFilter{
		Suffix: a,
	}
}

func (p *SuffixFilter) Filter(m dnstap.Message) bool {
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

	return strings.HasSuffix(questionName, p.Suffix)
}
