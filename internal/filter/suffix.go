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
	return strings.HasSuffix(questionName, p.Suffix)
}
