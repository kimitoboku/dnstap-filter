package transport

import (
	"fmt"
	"net"
	"os"

	"github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"
)

// DNSReplayOutput replays DNS query messages to a target server via UDP.
// Only query-type dnstap messages are sent; responses are silently skipped.
// The output is fire-and-forget: no DNS responses are read.
type DNSReplayOutput struct {
	target string
	ch     chan []byte
	done   chan struct{}
}

func newDNSReplayOutput(addr string) (*DNSReplayOutput, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port specified, default to 53.
		host = addr
		port = "53"
	}
	target := net.JoinHostPort(host, port)
	if _, err := net.ResolveUDPAddr("udp", target); err != nil {
		return nil, fmt.Errorf("dns output: invalid address %q: %w", addr, err)
	}
	return &DNSReplayOutput{
		target: target,
		ch:     make(chan []byte, 32),
		done:   make(chan struct{}),
	}, nil
}

func (d *DNSReplayOutput) GetOutputChannel() chan []byte {
	return d.ch
}

func (d *DNSReplayOutput) RunOutputLoop() {
	defer close(d.done)

	conn, err := net.Dial("udp", d.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns output: dial %s failed: %v\n", d.target, err)
		// Drain channel to avoid blocking the pipeline.
		for range d.ch {
		}
		return
	}
	defer conn.Close()

	dt := &dnstap.Dnstap{}
	for frame := range d.ch {
		if err := proto.Unmarshal(frame, dt); err != nil {
			fmt.Fprintf(os.Stderr, "dns output: proto.Unmarshal failed: %v\n", err)
			continue
		}
		if dt.Type == nil || *dt.Type != dnstap.Dnstap_MESSAGE || dt.Message == nil {
			continue
		}
		m := dt.Message
		if m.Type == nil || isResponseType(*m.Type) {
			continue
		}
		if m.QueryMessage == nil {
			continue
		}
		if _, err := conn.Write(m.QueryMessage); err != nil {
			fmt.Fprintf(os.Stderr, "dns output: write failed: %v\n", err)
		}
	}
}

func (d *DNSReplayOutput) Close() {
	close(d.ch)
	<-d.done
}
