package filter

import (
	"net"

	"github.com/dnstap/golang-dnstap"
)

type SubnetFilter struct {
	Net  *net.IPNet
	Mode AddrMode
}

func NewSubnetFilter(cidr string, mode AddrMode) *SubnetFilter {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return &SubnetFilter{Net: nil, Mode: mode}
	}
	return &SubnetFilter{Net: ipNet, Mode: mode}
}

func (p *SubnetFilter) Filter(m *dnstap.Message, _ *EvalContext) bool {
	switch p.Mode {
	case AddrSrc:
		return p.matchQuery(m)
	case AddrDst:
		return p.matchResponse(m)
	default:
		return p.matchQuery(m) || p.matchResponse(m)
	}
}

func (p *SubnetFilter) matchQuery(m *dnstap.Message) bool {
	if m.QueryAddress == nil {
		return false
	}
	return p.Net.Contains(net.IP(m.GetQueryAddress()))
}

func (p *SubnetFilter) matchResponse(m *dnstap.Message) bool {
	if m.ResponseAddress == nil {
		return false
	}
	return p.Net.Contains(net.IP(m.GetResponseAddress()))
}
