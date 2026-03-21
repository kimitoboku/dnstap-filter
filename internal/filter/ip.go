package filter

import (
	"net"

	"github.com/dnstap/golang-dnstap"
)

type IPFilter struct {
	IP   net.IP
	Mode AddrMode
}

func NewIPFilter(a string, mode AddrMode) *IPFilter {
	ip := net.ParseIP(a)
	return &IPFilter{
		IP:   ip,
		Mode: mode,
	}
}

func (p *IPFilter) Filter(m *dnstap.Message, _ *EvalContext) bool {
	switch p.Mode {
	case AddrSrc:
		return p.matchQuery(m)
	case AddrDst:
		return p.matchResponse(m)
	default:
		return p.matchQuery(m) || p.matchResponse(m)
	}
}

func (p *IPFilter) matchQuery(m *dnstap.Message) bool {
	if m.QueryAddress == nil {
		return false
	}
	return p.IP.Equal(net.IP(m.GetQueryAddress()))
}

func (p *IPFilter) matchResponse(m *dnstap.Message) bool {
	if m.ResponseAddress == nil {
		return false
	}
	return p.IP.Equal(net.IP(m.GetResponseAddress()))
}
