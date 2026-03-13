package filter

import (
	"fmt"
	"strings"

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
	Key    string
	Value  string
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

func FormatTree(root Node) string {
	return formatTree(root, 0)
}

func formatTree(node Node, depth int) string {
	if node == nil {
		return indent(depth) + "<nil>"
	}

	switch n := node.(type) {
	case *PredicateNode:
		if n.Key != "" {
			return indent(depth) + fmt.Sprintf("PREDICATE %s=%s", n.Key, n.Value)
		}
		return indent(depth) + "PREDICATE"
	case *AndNode:
		return indent(depth) + "AND\n" + formatTree(n.Left, depth+1) + "\n" + formatTree(n.Right, depth+1)
	case *OrNode:
		return indent(depth) + "OR\n" + formatTree(n.Left, depth+1) + "\n" + formatTree(n.Right, depth+1)
	default:
		return indent(depth) + fmt.Sprintf("UNKNOWN %T", node)
	}
}

func indent(depth int) string {
	return strings.Repeat("  ", depth)
}
