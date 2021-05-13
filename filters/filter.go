package filters

import (
	"github.com/dnstap/golang-dnstap"
)

type DnstapFilterFunc interface {
	Filter(msg dnstap.Message) bool
}
