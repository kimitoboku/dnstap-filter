package filter

import (
	"strconv"
	"time"

	"github.com/dnstap/golang-dnstap"
)

// TimeFilter matches messages whose timestamp is before or after a threshold.
type TimeFilter struct {
	Threshold time.Time
	After     bool // true = match >= threshold, false = match < threshold
}

// NewTimeFilter parses value as RFC3339 or Unix epoch seconds and returns a
// TimeFilter. after controls the comparison direction.
func NewTimeFilter(value string, after bool) (*TimeFilter, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		epoch, err2 := strconv.ParseInt(value, 10, 64)
		if err2 != nil {
			return nil, err // return original RFC3339 parse error
		}
		t = time.Unix(epoch, 0)
	}
	return &TimeFilter{Threshold: t, After: after}, nil
}

func (f *TimeFilter) Filter(m *dnstap.Message, _ *EvalContext) bool {
	t, ok := MessageTime(m)
	if !ok {
		return false
	}
	if f.After {
		return !t.Before(f.Threshold) // t >= threshold
	}
	return t.Before(f.Threshold) // t < threshold
}

// MessageTime extracts the timestamp from a dnstap message, preferring
// QueryTimeSec and falling back to ResponseTimeSec.
func MessageTime(m *dnstap.Message) (time.Time, bool) {
	if m.QueryTimeSec != nil {
		var nsec int64
		if m.QueryTimeNsec != nil {
			nsec = int64(*m.QueryTimeNsec)
		}
		return time.Unix(int64(*m.QueryTimeSec), nsec), true
	}
	if m.ResponseTimeSec != nil {
		var nsec int64
		if m.ResponseTimeNsec != nil {
			nsec = int64(*m.ResponseTimeNsec)
		}
		return time.Unix(int64(*m.ResponseTimeSec), nsec), true
	}
	return time.Time{}, false
}
