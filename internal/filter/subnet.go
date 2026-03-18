package filter

import (
	"net"

	"github.com/dnstap/golang-dnstap"
)

type SubnetFilter struct {
	Net *net.IPNet
}

func NewSubnetFilter(cidr string) *SubnetFilter {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return &SubnetFilter{Net: nil}
	}
	return &SubnetFilter{Net: ipNet}
}

func (p *SubnetFilter) Filter(m *dnstap.Message, _ *EvalContext) bool {
	if m.QueryAddress == nil {
		return false
	}
	ip := net.IP(m.GetQueryAddress())
	return p.Net.Contains(ip)
}
