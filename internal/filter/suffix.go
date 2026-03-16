package filter

import (
	"strings"

	"github.com/dnstap/golang-dnstap"
)

type SuffixFilter struct {
	Suffix string
}

func NewSuffixFilter(a string) *SuffixFilter {
	return &SuffixFilter{
		Suffix: a,
	}
}

func (p *SuffixFilter) Filter(m dnstap.Message, ctx *EvalContext) bool {
	msg := ctx.UnpackQueryOrResponse(m)
	if msg == nil {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	return strings.HasSuffix(msg.Question[0].Name, p.Suffix)
}
