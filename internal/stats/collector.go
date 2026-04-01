package stats

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

// RankedEntry is a key-count pair used for all distribution tables.
type RankedEntry struct {
	Key   string `json:"key" xml:"val,attr"`
	Count uint64 `json:"count" xml:"count,attr"`
}

// Snapshot holds a frozen copy of statistics for a single time window.
type Snapshot struct {
	Start       time.Time     `json:"start"`
	End         time.Time     `json:"end"`
	TotalFrames uint64        `json:"total_frames"`
	TopDomains  []RankedEntry `json:"top_domains"`
	QtypeDist   []RankedEntry `json:"qtype_distribution"`
	RcodeDist   []RankedEntry `json:"rcode_distribution"`
	ClientIPs   []RankedEntry `json:"client_ips"`
}

// CollectorOptions controls how the Collector aggregates statistics.
type CollectorOptions struct {
	// TopN is the maximum number of entries kept in domain and client IP
	// rankings. Default: 20.
	TopN int

	// DomainLabels controls domain name aggregation. When > 0, query names
	// are truncated to the last N DNS labels before counting. For example,
	// with DomainLabels=2, both "www.example.com." and "mail.example.com."
	// are counted as "example.com.". 0 means full qname (no aggregation).
	DomainLabels int

	// SubnetPrefix masks client IP addresses to a prefix length before
	// counting, grouping addresses into subnets. For example, SubnetPrefix=24
	// groups all IPs in the same /24 together (e.g. "192.0.2.0/24").
	// 0 means no masking (use the full address).
	SubnetPrefix int

	// WindowDuration is the size of each time window for automatic rotation
	// based on message timestamps. When > 0, Record() rotates the current
	// window whenever a message's timestamp crosses a window boundary. This
	// ensures that windows in the output report reflect DNS traffic time
	// rather than wall-clock processing time, which is important when
	// replaying dnstap or pcap files. 0 disables automatic rotation.
	WindowDuration time.Duration
}

// Collector accumulates DNS statistics from dnstap messages.
// It is safe for concurrent use from a single writer goroutine
// plus multiple reader goroutines.
type Collector struct {
	mu       sync.Mutex
	opts     CollectorOptions
	current  *window
	history  []*Snapshot
	allTime  *window
	lastTime time.Time // timestamp of the last recorded message (zero = not yet seen)
}

// NewCollector creates a new Collector with the given options.
func NewCollector(opts CollectorOptions) *Collector {
	if opts.TopN <= 0 {
		opts.TopN = 20
	}
	return &Collector{
		opts: opts,
	}
}

// messageTime extracts the timestamp from a dnstap message.
// It prefers the query timestamp; falls back to response timestamp.
// Returns the zero value if neither is set.
func messageTime(msg *dnstap.Message) time.Time {
	if msg.QueryTimeSec != nil {
		t := time.Unix(int64(*msg.QueryTimeSec), 0).UTC()
		if msg.QueryTimeNsec != nil {
			t = t.Add(time.Duration(*msg.QueryTimeNsec))
		}
		return t
	}
	if msg.ResponseTimeSec != nil {
		t := time.Unix(int64(*msg.ResponseTimeSec), 0).UTC()
		if msg.ResponseTimeNsec != nil {
			t = t.Add(time.Duration(*msg.ResponseTimeNsec))
		}
		return t
	}
	return time.Time{}
}

// Record records a single dnstap message into the current window and
// the all-time accumulator. The dnsMsg parameter should be the already-
// unpacked DNS message from EvalContext to avoid redundant unpacking.
// If dnsMsg is nil, the message is still counted but DNS-level fields
// (qname, qtype, rcode) are not recorded.
//
// When CollectorOptions.WindowDuration > 0, Record automatically rotates
// the current window whenever the message timestamp crosses a window
// boundary, so that time windows reflect DNS traffic time rather than
// wall-clock time.
func (c *Collector) Record(msg *dnstap.Message, dnsMsg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := messageTime(msg)
	if !t.IsZero() {
		// Initialise windows lazily on the first message with a timestamp.
		if c.current == nil {
			start := t.Truncate(c.opts.WindowDuration)
			if c.opts.WindowDuration <= 0 {
				start = t
			}
			c.current = newWindow(start)
			c.allTime = newWindow(start)
		}
		c.lastTime = t

		// Auto-rotate when WindowDuration is set and the message has moved
		// past the current window boundary.
		if c.opts.WindowDuration > 0 {
			windowEnd := c.current.start.Add(c.opts.WindowDuration)
			for !t.Before(windowEnd) {
				snap := c.current.snapshot(windowEnd, c.opts.TopN)
				c.history = append(c.history, snap)
				c.current = newWindow(windowEnd)
				windowEnd = c.current.start.Add(c.opts.WindowDuration)
			}
		}
	} else if c.current == nil {
		// No timestamp at all: fall back to wall clock.
		now := time.Now()
		c.current = newWindow(now)
		c.allTime = newWindow(now)
	}

	c.current.totalFrames++
	c.allTime.totalFrames++

	// Client IP from QueryAddress.
	if msg.QueryAddress != nil {
		ip := c.normalizeIP(msg.QueryAddress)
		c.current.clientIPs[ip]++
		c.allTime.clientIPs[ip]++
	}

	if dnsMsg == nil {
		return
	}

	// Query name and type from the first question.
	if len(dnsMsg.Question) > 0 {
		qname := c.normalizeDomain(dnsMsg.Question[0].Name)
		c.current.domains[qname]++
		c.allTime.domains[qname]++

		qtype := dnsMsg.Question[0].Qtype
		c.current.qtypes[qtype]++
		c.allTime.qtypes[qtype]++
	}

	// Response code (only meaningful for responses, but we record it
	// unconditionally since the caller may filter by msgtype).
	if msg.Type != nil && isResponseType(*msg.Type) {
		rcode := dnsMsg.Rcode
		c.current.rcodes[rcode]++
		c.allTime.rcodes[rcode]++
	}
}

// normalizeDomain applies label-level aggregation to a DNS name.
func (c *Collector) normalizeDomain(qname string) string {
	if c.opts.DomainLabels <= 0 {
		return qname
	}
	labels := dns.SplitDomainName(qname) // returns labels without trailing dot
	if labels == nil || len(labels) <= c.opts.DomainLabels {
		return qname
	}
	return strings.Join(labels[len(labels)-c.opts.DomainLabels:], ".") + "."
}

// normalizeIP applies subnet masking to a raw IP address byte slice.
func (c *Collector) normalizeIP(rawIP []byte) string {
	ip := net.IP(rawIP)
	if c.opts.SubnetPrefix <= 0 {
		return ip.String()
	}
	ip4 := ip.To4()
	if ip4 != nil {
		mask := net.CIDRMask(c.opts.SubnetPrefix, 32)
		return fmt.Sprintf("%s/%d", ip4.Mask(mask).String(), c.opts.SubnetPrefix)
	}
	mask := net.CIDRMask(c.opts.SubnetPrefix, 128)
	return fmt.Sprintf("%s/%d", ip.Mask(mask).String(), c.opts.SubnetPrefix)
}

// Rotate closes the current window, converts it to a Snapshot, appends
// it to history, and opens a new window. Returns the completed snapshot.
// It is called by StatsOutput on ticker ticks (wall-clock rotation) or at
// close time. When message timestamps are available, the window end time
// is taken from the last recorded message rather than the wall clock.
func (c *Collector) Rotate() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	end := c.effectiveNow()
	if c.current == nil {
		c.current = newWindow(end)
		c.allTime = newWindow(end)
	}
	snap := c.current.snapshot(end, c.opts.TopN)
	c.history = append(c.history, snap)
	c.current = newWindow(end)
	return snap
}

// AllTimeSnapshot returns a snapshot of the cumulative statistics.
func (c *Collector) AllTimeSnapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.allTime == nil {
		now := time.Now()
		return newWindow(now).snapshot(now, c.opts.TopN)
	}
	return c.allTime.snapshot(c.effectiveNow(), c.opts.TopN)
}

// effectiveNow returns the last message timestamp if available, otherwise
// the wall-clock time. Must be called with c.mu held.
func (c *Collector) effectiveNow() time.Time {
	if !c.lastTime.IsZero() {
		return c.lastTime
	}
	return time.Now()
}

// History returns a copy of the completed window snapshots.
func (c *Collector) History() []*Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Snapshot, len(c.history))
	copy(out, c.history)
	return out
}

// isResponseType returns true if the dnstap message type is a response.
func isResponseType(mt dnstap.Message_Type) bool {
	return int32(mt)%2 == 0
}

// rankTopN sorts a map by count descending and returns the top N entries.
func rankTopN(m map[string]uint64, n int) []RankedEntry {
	entries := make([]RankedEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, RankedEntry{Key: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// rankAll converts a typed map to a sorted RankedEntry slice (all entries).
func rankAll[K comparable](m map[K]uint64, keyStr func(K) string) []RankedEntry {
	entries := make([]RankedEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, RankedEntry{Key: keyStr(k), Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	return entries
}

// qtypeString returns the DNS type name for a given numeric qtype.
func qtypeString(qtype uint16) string {
	if s, ok := dns.TypeToString[qtype]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

// rcodeString returns the DNS rcode name for a given numeric rcode.
func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
