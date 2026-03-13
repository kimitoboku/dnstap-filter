package filters

import (
	"github.com/dnstap/golang-dnstap"
)

type DnstapFilterFunc interface {
	Filter(msg dnstap.Message) bool
}

type Node interface {
	Eval(msg dnstap.Message) bool
}

type PredicateNode struct {
	Filter DnstapFilterFunc
}

func (n *PredicateNode) Eval(msg dnstap.Message) bool {
	if n == nil || n.Filter == nil {
		return false
	}
	return n.Filter.Filter(msg)
}

type AndNode struct {
	Left  Node
	Right Node
}

func (n *AndNode) Eval(msg dnstap.Message) bool {
	if n == nil || n.Left == nil || n.Right == nil {
		return false
	}
	return n.Left.Eval(msg) && n.Right.Eval(msg)
}

type OrNode struct {
	Left  Node
	Right Node
}

func (n *OrNode) Eval(msg dnstap.Message) bool {
	if n == nil || n.Left == nil || n.Right == nil {
		return false
	}
	return n.Left.Eval(msg) || n.Right.Eval(msg)
}
