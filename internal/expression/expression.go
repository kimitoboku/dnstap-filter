package expression

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/kimitoboku/dnstap-filter/internal/filter"
)

type tokenType int

const (
	tokenWord tokenType = iota
	tokenAnd
	tokenOr
	tokenNot
	tokenLParen
	tokenRParen
)

type token struct {
	typ   tokenType
	lit   string
	index int
	pos   int
}

type parser struct {
	tokens []token
	pos    int
}

func ParseFilterExpression(expr string) (filter.Node, error) {
	tokens, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return &filter.MatchAllNode{}, nil
	}

	p := &parser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.hasNext() {
		tok := p.peek()
		return nil, fmt.Errorf("token %d at char %d ('%s'): unexpected token", tok.index, tok.pos, tok.lit)
	}

	return node, nil
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	tokenIndex := 0

	for i := 0; i < len(input); {
		r := rune(input[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}

		switch input[i] {
		case '(':
			tokens = append(tokens, token{typ: tokenLParen, lit: "(", index: tokenIndex, pos: i})
			tokenIndex++
			i++
			continue
		case ')':
			tokens = append(tokens, token{typ: tokenRParen, lit: ")", index: tokenIndex, pos: i})
			tokenIndex++
			i++
			continue
		}

		start := i
		for i < len(input) {
			if input[i] == '(' || input[i] == ')' || unicode.IsSpace(rune(input[i])) {
				break
			}
			i++
		}
		word := input[start:i]
		if word == "" {
			return nil, fmt.Errorf("token %d at char %d: invalid token", tokenIndex, start)
		}

		switch {
		case strings.EqualFold(word, "and"):
			tokens = append(tokens, token{typ: tokenAnd, lit: word, index: tokenIndex, pos: start})
		case strings.EqualFold(word, "or"):
			tokens = append(tokens, token{typ: tokenOr, lit: word, index: tokenIndex, pos: start})
		case strings.EqualFold(word, "not"):
			tokens = append(tokens, token{typ: tokenNot, lit: word, index: tokenIndex, pos: start})
		default:
			tokens = append(tokens, token{typ: tokenWord, lit: word, index: tokenIndex, pos: start})
		}
		tokenIndex++
	}

	return tokens, nil
}

func (p *parser) parseOr() (filter.Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.match(tokenOr) {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &filter.OrNode{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (filter.Node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.match(tokenAnd) {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &filter.AndNode{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseNot() (filter.Node, error) {
	if p.match(tokenNot) {
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &filter.NotNode{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (filter.Node, error) {
	if p.match(tokenLParen) {
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(tokenRParen) {
			if p.hasNext() {
				tok := p.peek()
				return nil, fmt.Errorf("token %d at char %d ('%s'): expected ')'", tok.index, tok.pos, tok.lit)
			}
			return nil, fmt.Errorf("end of expression: expected ')' after group")
		}
		return node, nil
	}

	if !p.hasNext() {
		return nil, fmt.Errorf("end of expression: expected predicate")
	}

	tok := p.peek()
	if tok.typ != tokenWord {
		return nil, fmt.Errorf("token %d at char %d ('%s'): expected predicate", tok.index, tok.pos, tok.lit)
	}
	p.pos++
	return parsePredicate(tok)
}

func parsePredicate(tok token) (filter.Node, error) {
	parts := strings.SplitN(tok.lit, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("token %d at char %d ('%s'): predicate must be key=value", tok.index, tok.pos, tok.lit)
	}

	key := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return nil, fmt.Errorf("token %d at char %d ('%s'): empty predicate key", tok.index, tok.pos, tok.lit)
	}
	if value == "" {
		return nil, fmt.Errorf("token %d at char %d ('%s'): empty predicate value", tok.index, tok.pos, tok.lit)
	}

	switch key {
	case "ip":
		f := filter.NewIPFilter(value)
		if f.IP == nil {
			return nil, fmt.Errorf("token %d at char %d ('%s'): invalid ip value", tok.index, tok.pos, tok.lit)
		}
		return &filter.PredicateNode{Filter: f, Key: key, Value: value}, nil
	case "fqdn":
		return &filter.PredicateNode{Filter: filter.NewFQDNFilter(value), Key: key, Value: value}, nil
	case "suffix":
		return &filter.PredicateNode{Filter: filter.NewSuffixFilter(value), Key: key, Value: value}, nil
	case "rcode":
		return &filter.PredicateNode{Filter: filter.NewRcodeFilter(value), Key: key, Value: value}, nil
	case "subnet":
		f := filter.NewSubnetFilter(value)
		if f.Net == nil {
			return nil, fmt.Errorf("token %d at char %d ('%s'): invalid CIDR value", tok.index, tok.pos, tok.lit)
		}
		return &filter.PredicateNode{Filter: f, Key: key, Value: value}, nil
	case "qtype":
		f := filter.NewQtypeFilter(value)
		if f == nil {
			return nil, fmt.Errorf("token %d at char %d ('%s'): unknown DNS type %q", tok.index, tok.pos, tok.lit, value)
		}
		return &filter.PredicateNode{Filter: f, Key: key, Value: value}, nil
	case "rdata":
		f, err := filter.NewRdataFilter(value)
		if err != nil {
			return nil, fmt.Errorf("token %d at char %d ('%s'): %w", tok.index, tok.pos, tok.lit, err)
		}
		return &filter.PredicateNode{Filter: f, Key: key, Value: value}, nil
	case "msgtype":
		f := filter.NewMsgTypeFilter(value)
		if f == nil {
			return nil, fmt.Errorf("token %d at char %d ('%s'): unknown message type %q", tok.index, tok.pos, tok.lit, value)
		}
		return &filter.PredicateNode{Filter: f, Key: key, Value: value}, nil
	default:
		return nil, fmt.Errorf("token %d at char %d ('%s'): unknown predicate key '%s'", tok.index, tok.pos, tok.lit, key)
	}
}

func (p *parser) hasNext() bool {
	return p.pos < len(p.tokens)
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) match(t tokenType) bool {
	if !p.hasNext() {
		return false
	}
	if p.tokens[p.pos].typ != t {
		return false
	}
	p.pos++
	return true
}
