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
}

// Collector accumulates DNS statistics from dnstap messages.
// It is safe for concurrent use from a single writer goroutine
// plus multiple reader goroutines.
type Collector struct {
	mu      sync.Mutex
	opts    CollectorOptions
	current *window
	history []*Snapshot
	allTime *window
}

// NewCollector creates a new Collector with the given options.
func NewCollector(opts CollectorOptions) *Collector {
	if opts.TopN <= 0 {
		opts.TopN = 20
	}
	now := time.Now()
	return &Collector{
		opts:    opts,
		current: newWindow(now),
		allTime: newWindow(now),
	}
}

// Record records a single dnstap message into the current window and
// the all-time accumulator. The dnsMsg parameter should be the already-
// unpacked DNS message from EvalContext to avoid redundant unpacking.
// If dnsMsg is nil, the message is still counted but DNS-level fields
// (qname, qtype, rcode) are not recorded.
func (c *Collector) Record(msg *dnstap.Message, dnsMsg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
func (c *Collector) Rotate() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	snap := c.current.snapshot(now, c.opts.TopN)
	c.history = append(c.history, snap)
	c.current = newWindow(now)
	return snap
}

// AllTimeSnapshot returns a snapshot of the cumulative statistics.
func (c *Collector) AllTimeSnapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allTime.snapshot(time.Now(), c.opts.TopN)
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
