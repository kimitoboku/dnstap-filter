package filter

import (
	"fmt"
	"strings"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

// EvalContext caches parsed DNS messages across filter evaluations for a single
// dnstap message, avoiding redundant dns.Msg.Unpack calls.
type EvalContext struct {
	queryMsg         *dns.Msg
	responseMsg      *dns.Msg
	queryUnpacked    bool
	responseUnpacked bool
}

// NewEvalContext returns a fresh EvalContext.
func NewEvalContext() *EvalContext {
	return &EvalContext{}
}

// Reset clears the cached state so the context can be reused for a new message.
func (ctx *EvalContext) Reset() {
	ctx.queryMsg = nil
	ctx.responseMsg = nil
	ctx.queryUnpacked = false
	ctx.responseUnpacked = false
}

// UnpackQuery returns the parsed query DNS message, caching the result.
func (ctx *EvalContext) UnpackQuery(m *dnstap.Message) *dns.Msg {
	if ctx.queryUnpacked {
		return ctx.queryMsg
	}
	ctx.queryUnpacked = true
	if m.QueryMessage == nil {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(m.QueryMessage); err != nil {
		return nil
	}
	ctx.queryMsg = msg
	return msg
}

// UnpackResponse returns the parsed response DNS message, caching the result.
func (ctx *EvalContext) UnpackResponse(m *dnstap.Message) *dns.Msg {
	if ctx.responseUnpacked {
		return ctx.responseMsg
	}
	ctx.responseUnpacked = true
	if m.ResponseMessage == nil {
		return nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(m.ResponseMessage); err != nil {
		return nil
	}
	ctx.responseMsg = msg
	return msg
}

// UnpackQueryOrResponse returns the parsed query message if available,
// otherwise the response message.
func (ctx *EvalContext) UnpackQueryOrResponse(m *dnstap.Message) *dns.Msg {
	if m.QueryMessage != nil {
		return ctx.UnpackQuery(m)
	}
	return ctx.UnpackResponse(m)
}

type DnstapFilterFunc interface {
	Filter(msg *dnstap.Message, ctx *EvalContext) bool
}

type Node interface {
	Eval(msg *dnstap.Message, ctx *EvalContext) bool
}

type PredicateNode struct {
	Filter DnstapFilterFunc
	Key    string
	Value  string
}

func (n *PredicateNode) Eval(msg *dnstap.Message, ctx *EvalContext) bool {
	if n == nil || n.Filter == nil {
		return false
	}
	return n.Filter.Filter(msg, ctx)
}

type AndNode struct {
	Left  Node
	Right Node
}

func (n *AndNode) Eval(msg *dnstap.Message, ctx *EvalContext) bool {
	if n == nil || n.Left == nil || n.Right == nil {
		return false
	}
	return n.Left.Eval(msg, ctx) && n.Right.Eval(msg, ctx)
}

type OrNode struct {
	Left  Node
	Right Node
}

func (n *OrNode) Eval(msg *dnstap.Message, ctx *EvalContext) bool {
	if n == nil || n.Left == nil || n.Right == nil {
		return false
	}
	return n.Left.Eval(msg, ctx) || n.Right.Eval(msg, ctx)
}

type NotNode struct {
	Child Node
}

func (n *NotNode) Eval(msg *dnstap.Message, ctx *EvalContext) bool {
	if n == nil || n.Child == nil {
		return false
	}
	return !n.Child.Eval(msg, ctx)
}

type MatchAllNode struct{}

func (n *MatchAllNode) Eval(_ *dnstap.Message, _ *EvalContext) bool {
	return true
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
	case *NotNode:
		return indent(depth) + "NOT\n" + formatTree(n.Child, depth+1)
	case *OrNode:
		return indent(depth) + "OR\n" + formatTree(n.Left, depth+1) + "\n" + formatTree(n.Right, depth+1)
	case *MatchAllNode:
		return indent(depth) + "MATCH_ALL"
	default:
		return indent(depth) + fmt.Sprintf("UNKNOWN %T", node)
	}
}

func indent(depth int) string {
	return strings.Repeat("  ", depth)
}

// nodeCost returns a static cost estimate for evaluating a node.
func nodeCost(n Node) int {
	switch n := n.(type) {
	case *PredicateNode:
		switch n.Key {
		case "ip", "subnet", "msgtype":
			return 1
		default:
			return 10
		}
	case *MatchAllNode:
		return 0
	case *NotNode:
		return nodeCost(n.Child)
	case *AndNode:
		return nodeCost(n.Left) + nodeCost(n.Right)
	case *OrNode:
		return nodeCost(n.Left) + nodeCost(n.Right)
	default:
		return 10
	}
}

// OptimizeTree reorders AND/OR children so that cheaper predicates are
// evaluated first, maximizing the benefit of short-circuit evaluation.
func OptimizeTree(root Node) Node {
	if root == nil {
		return nil
	}
	switch n := root.(type) {
	case *AndNode:
		left := OptimizeTree(n.Left)
		right := OptimizeTree(n.Right)
		if nodeCost(right) < nodeCost(left) {
			return &AndNode{Left: right, Right: left}
		}
		return &AndNode{Left: left, Right: right}
	case *OrNode:
		left := OptimizeTree(n.Left)
		right := OptimizeTree(n.Right)
		if nodeCost(right) < nodeCost(left) {
			return &OrNode{Left: right, Right: left}
		}
		return &OrNode{Left: left, Right: right}
	case *NotNode:
		return &NotNode{Child: OptimizeTree(n.Child)}
	default:
		return root
	}
}
