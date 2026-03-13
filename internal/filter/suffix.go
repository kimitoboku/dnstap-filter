package filter

import (
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
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
	msg := new(dns.Msg)
	if m.QueryAddress != nil {
		err := msg.Unpack(m.QueryMessage)
		if err != nil {
			return false
		}
	} else if m.ResponseAddress != nil {
		err := msg.Unpack(m.ResponseMessage)
		if err != nil {
			return false
		}
	} else {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	questionName := msg.Question[0].Name
	return strings.HasSuffix(questionName, p.Suffix)
}
