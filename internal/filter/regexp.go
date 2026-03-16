package filter

import (
	"regexp"

	"github.com/dnstap/golang-dnstap"
)

type RegexpFilter struct {
	Re *regexp.Regexp
}

func NewRegexpFilter(pattern string) (*RegexpFilter, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexpFilter{
		Re: re,
	}, nil
}

func (p *RegexpFilter) Filter(m dnstap.Message, ctx *EvalContext) bool {
	msg := ctx.UnpackQueryOrResponse(m)
	if msg == nil {
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	return p.Re.MatchString(msg.Question[0].Name)
}
