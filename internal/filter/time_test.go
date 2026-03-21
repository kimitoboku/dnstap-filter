package filter

import (
	"testing"
	"time"

	"github.com/dnstap/golang-dnstap"
)

func uint64p(v uint64) *uint64 { return &v }
func uint32p(v uint32) *uint32 { return &v }

func TestTimeFilter_After(t *testing.T) {
	threshold := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	f := &TimeFilter{Threshold: threshold, After: true}
	ctx := NewEvalContext()

	// Message exactly at threshold — should match (>=)
	sec := uint64(threshold.Unix())
	msg := &dnstap.Message{QueryTimeSec: &sec}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for time == threshold")
	}

	// Message after threshold
	after := uint64(threshold.Add(time.Hour).Unix())
	msg = &dnstap.Message{QueryTimeSec: &after}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for time > threshold")
	}

	// Message before threshold — should not match
	before := uint64(threshold.Add(-time.Hour).Unix())
	msg = &dnstap.Message{QueryTimeSec: &before}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for time < threshold")
	}
}

func TestTimeFilter_Before(t *testing.T) {
	threshold := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	f := &TimeFilter{Threshold: threshold, After: false}
	ctx := NewEvalContext()

	// Message before threshold — should match
	before := uint64(threshold.Add(-time.Hour).Unix())
	msg := &dnstap.Message{QueryTimeSec: &before}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for time < threshold")
	}

	// Message exactly at threshold — should not match (<)
	sec := uint64(threshold.Unix())
	msg = &dnstap.Message{QueryTimeSec: &sec}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for time == threshold")
	}

	// Message after threshold — should not match
	after := uint64(threshold.Add(time.Hour).Unix())
	msg = &dnstap.Message{QueryTimeSec: &after}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for time > threshold")
	}
}

func TestTimeFilter_NoTimestamp(t *testing.T) {
	f := &TimeFilter{Threshold: time.Now(), After: true}
	ctx := NewEvalContext()

	msg := &dnstap.Message{}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for message without timestamp")
	}
}

func TestTimeFilter_ResponseTimeFallback(t *testing.T) {
	threshold := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	f := &TimeFilter{Threshold: threshold, After: true}
	ctx := NewEvalContext()

	// No QueryTimeSec, but ResponseTimeSec is after threshold
	after := uint64(threshold.Add(time.Hour).Unix())
	msg := &dnstap.Message{ResponseTimeSec: &after}
	if !f.Filter(msg, ctx) {
		t.Error("expected match using ResponseTimeSec fallback")
	}
}

func TestTimeFilter_Nanoseconds(t *testing.T) {
	// Threshold at exactly T+0.5s
	threshold := time.Date(2024, 6, 15, 0, 0, 0, 500000000, time.UTC)
	f := &TimeFilter{Threshold: threshold, After: true}
	ctx := NewEvalContext()

	sec := uint64(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC).Unix())

	// Same second but nsec < threshold nsec — should not match
	nsec1 := uint32(100000000) // 0.1s
	msg := &dnstap.Message{QueryTimeSec: &sec, QueryTimeNsec: &nsec1}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for nsec before threshold")
	}

	// Same second but nsec >= threshold nsec — should match
	nsec2 := uint32(500000000) // 0.5s
	msg = &dnstap.Message{QueryTimeSec: &sec, QueryTimeNsec: &nsec2}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for nsec == threshold")
	}
}

func TestNewTimeFilter_RFC3339(t *testing.T) {
	f, err := NewTimeFilter("2024-06-15T12:30:00Z", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)
	if !f.Threshold.Equal(expected) {
		t.Errorf("got %v, want %v", f.Threshold, expected)
	}
}

func TestNewTimeFilter_RFC3339_JST(t *testing.T) {
	// JST is UTC+9
	f, err := NewTimeFilter("2024-06-15T21:30:00+09:00", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2024-06-15T21:30:00+09:00 == 2024-06-15T12:30:00Z
	expected := time.Date(2024, 6, 15, 12, 30, 0, 0, time.UTC)
	if !f.Threshold.Equal(expected) {
		t.Errorf("got %v, want %v (UTC equivalent)", f.Threshold, expected)
	}
}

func TestTimeFilter_JST_MatchesCorrectRange(t *testing.T) {
	// Filter: after 2024-06-15T09:00:00+09:00 (== 2024-06-15T00:00:00Z)
	f, err := NewTimeFilter("2024-06-15T09:00:00+09:00", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx := NewEvalContext()

	// Message at 2024-06-14T23:59:59Z — before threshold, should not match
	before := uint64(time.Date(2024, 6, 14, 23, 59, 59, 0, time.UTC).Unix())
	msg := &dnstap.Message{QueryTimeSec: &before}
	if f.Filter(msg, ctx) {
		t.Error("expected no match for time before JST threshold")
	}

	// Message at 2024-06-15T00:00:00Z — exactly at threshold, should match
	at := uint64(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC).Unix())
	msg = &dnstap.Message{QueryTimeSec: &at}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for time == JST threshold")
	}

	// Message at 2024-06-15T00:00:01Z — after threshold, should match
	after := uint64(time.Date(2024, 6, 15, 0, 0, 1, 0, time.UTC).Unix())
	msg = &dnstap.Message{QueryTimeSec: &after}
	if !f.Filter(msg, ctx) {
		t.Error("expected match for time after JST threshold")
	}
}

func TestNewTimeFilter_UnixEpoch(t *testing.T) {
	f, err := NewTimeFilter("1718451000", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Unix(1718451000, 0)
	if !f.Threshold.Equal(expected) {
		t.Errorf("got %v, want %v", f.Threshold, expected)
	}
}

func TestNewTimeFilter_InvalidValue(t *testing.T) {
	_, err := NewTimeFilter("not-a-time", true)
	if err == nil {
		t.Error("expected error for invalid time value")
	}
}
