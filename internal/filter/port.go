package filter

import (
	"strconv"

	"github.com/dnstap/golang-dnstap"
)

type PortFilter struct {
	Port uint32
	Mode AddrMode
}

func NewPortFilter(portStr string, mode AddrMode) *PortFilter {
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil
	}
	return &PortFilter{
		Port: uint32(p),
		Mode: mode,
	}
}

func (p *PortFilter) Filter(m *dnstap.Message, _ *EvalContext) bool {
	switch p.Mode {
	case AddrSrc:
		return p.matchQuery(m)
	case AddrDst:
		return p.matchResponse(m)
	default:
		return p.matchQuery(m) || p.matchResponse(m)
	}
}

func (p *PortFilter) matchQuery(m *dnstap.Message) bool {
	if m.QueryPort == nil {
		return false
	}
	return m.GetQueryPort() == p.Port
}

func (p *PortFilter) matchResponse(m *dnstap.Message) bool {
	if m.ResponsePort == nil {
		return false
	}
	return m.GetResponsePort() == p.Port
}
