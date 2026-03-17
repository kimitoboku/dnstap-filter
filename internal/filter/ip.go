package filter

import (
	"net"

	"github.com/dnstap/golang-dnstap"
)

type IPFilter struct {
	IP net.IP
}

func NewIPFilter(a string) *IPFilter {
	ip := net.ParseIP(a)
	return &IPFilter{
		IP: ip,
	}
}

func (p *IPFilter) Filter(m dnstap.Message, _ *EvalContext) bool {
	if m.QueryAddress == nil {
		return false
	}
	ip := net.IP(m.GetQueryAddress())
	return p.IP.Equal(ip)
}
