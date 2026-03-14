package filter

import (
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type QtypeFilter struct {
	Qtype uint16
}

// NewQtypeFilter parses a DNS type name (e.g. "A", "AAAA", "MX") and returns
// a *QtypeFilter. Returns nil if the type name is not recognised.
func NewQtypeFilter(typeName string) *QtypeFilter {
	t, ok := dns.StringToType[strings.ToUpper(typeName)]
	if !ok {
		return nil
	}
	return &QtypeFilter{Qtype: t}
}

func (p *QtypeFilter) Filter(m dnstap.Message) bool {
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

	return msg.Question[0].Qtype == p.Qtype
}
