package filter

import (
	"fmt"
	"net"
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

type rdataMatchMode int

const (
	rdataModeIP     rdataMatchMode = iota // exact IP match against A/AAAA
	rdataModeSubnet                       // CIDR subnet match against A/AAAA
	rdataModeTXT                          // substring match against TXT records
)

type RdataFilter struct {
	mode   rdataMatchMode
	ip     net.IP
	subnet *net.IPNet
	text   string
}

// NewRdataFilter constructs an RdataFilter. The match mode is determined by
// the value format:
//   - Valid IP address → exact match against A/AAAA answer records
//   - Contains "/" and valid CIDR → subnet match against A/AAAA answer records
//   - Otherwise → substring match against TXT answer records
func NewRdataFilter(value string) (*RdataFilter, error) {
	if ip := net.ParseIP(value); ip != nil {
		return &RdataFilter{mode: rdataModeIP, ip: ip}, nil
	}

	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR value %q: %w", value, err)
		}
		return &RdataFilter{mode: rdataModeSubnet, subnet: ipNet}, nil
	}

	return &RdataFilter{mode: rdataModeTXT, text: value}, nil
}

func (p *RdataFilter) Filter(m dnstap.Message) bool {
	if m.ResponseMessage == nil {
		return false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(m.ResponseMessage); err != nil {
		return false
	}

	for _, rr := range msg.Answer {
		switch p.mode {
		case rdataModeIP:
			if a, ok := rr.(*dns.A); ok && p.ip.Equal(a.A) {
				return true
			}
			if aaaa, ok := rr.(*dns.AAAA); ok && p.ip.Equal(aaaa.AAAA) {
				return true
			}
		case rdataModeSubnet:
			if a, ok := rr.(*dns.A); ok && p.subnet.Contains(a.A) {
				return true
			}
			if aaaa, ok := rr.(*dns.AAAA); ok && p.subnet.Contains(aaaa.AAAA) {
				return true
			}
		case rdataModeTXT:
			if txt, ok := rr.(*dns.TXT); ok {
				if strings.Contains(strings.Join(txt.Txt, ""), p.text) {
					return true
				}
			}
		}
	}

	return false
}
