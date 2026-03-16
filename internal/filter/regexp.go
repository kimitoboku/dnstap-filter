package filter

import (
	"regexp"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type RegexpFilter struct {
	Re *regexp.Regexp
}

func NewRegexpFilter(pattern string) (*RegexpFilter, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexpFilter{
		Re: re,
	}, nil
}

func (p *RegexpFilter) Filter(m dnstap.Message) bool {
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
	return p.Re.MatchString(questionName)
}
