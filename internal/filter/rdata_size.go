package filter

import (
	"fmt"
	"strconv"

	"github.com/dnstap/golang-dnstap"
)

type RdataSizeFilter struct {
	size int
}

func NewRdataSizeFilter(value string) (*RdataSizeFilter, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return nil, fmt.Errorf("invalid rdata.size value %q: %w", value, err)
	}
	if n < 0 {
		return nil, fmt.Errorf("rdata.size must be non-negative, got %d", n)
	}
	return &RdataSizeFilter{size: n}, nil
}

func (f *RdataSizeFilter) Filter(m *dnstap.Message, ctx *EvalContext) bool {
	if m.ResponseMessage == nil {
		return false
	}

	msg := ctx.UnpackResponse(m)
	if msg == nil {
		return false
	}

	return len(msg.Answer) == f.size
}
