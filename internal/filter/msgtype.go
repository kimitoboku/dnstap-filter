package filter

import (
	"strings"

	"github.com/dnstap/golang-dnstap"
)

type MsgTypeFilter struct {
	MsgType int32
}

// NewMsgTypeFilter parses a dnstap message type name (e.g. "CLIENT_QUERY",
// "CLIENT_RESPONSE") and returns a *MsgTypeFilter.
// Returns nil if the name is not recognised.
func NewMsgTypeFilter(typeName string) *MsgTypeFilter {
	val, ok := dnstap.Message_Type_value[strings.ToUpper(typeName)]
	if !ok {
		return nil
	}
	return &MsgTypeFilter{MsgType: val}
}

func (p *MsgTypeFilter) Filter(m dnstap.Message) bool {
	if m.Type == nil {
		return false
	}
	return int32(*m.Type) == p.MsgType
}
