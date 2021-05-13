package filters

import (
	"github.com/dnstap/golang-dnstap"
	"net"
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

func (p *IPFilter) Filter(m dnstap.Message) bool {
	var ip net.IP
	if m.QueryAddress != nil {
		queryAddress := m.GetQueryAddress()
		ip = net.IP(queryAddress)
	}

	if m.ResponseAddress != nil {
		responseAddress := m.GetResponseAddress()
		ip = net.IP(responseAddress)
	}

	return p.IP.String() == ip.String()
}
