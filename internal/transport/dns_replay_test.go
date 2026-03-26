package transport

import (
	"net"
	"testing"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestDNSReplayOutput_SendsQueries(t *testing.T) {
	// Start a local UDP listener to receive replayed queries.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()
	out, err := newDNSReplayOutput(addr)
	if err != nil {
		t.Fatalf("newDNSReplayOutput(%q): %v", addr, err)
	}
	go out.RunOutputLoop()

	// Build a CLIENT_QUERY dnstap frame.
	dt := buildTestDnstap(dnstap.Message_CLIENT_QUERY, "www.example.com.", dns.TypeA, 0, nil)
	frame, err := proto.Marshal(dt)
	if err != nil {
		t.Fatal(err)
	}

	out.GetOutputChannel() <- frame

	// Read the replayed packet from the listener.
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive replayed query: %v", err)
	}

	// Verify the received bytes are a valid DNS query for www.example.com.
	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		t.Fatalf("received invalid DNS message: %v", err)
	}
	if len(msg.Question) == 0 {
		t.Fatal("received DNS message has no questions")
	}
	if msg.Question[0].Name != "www.example.com." {
		t.Errorf("expected qname www.example.com., got %s", msg.Question[0].Name)
	}
	if msg.Question[0].Qtype != dns.TypeA {
		t.Errorf("expected qtype A, got %s", dns.Type(msg.Question[0].Qtype).String())
	}

	out.Close()
}

func TestDNSReplayOutput_SkipsResponses(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().String()
	out, err := newDNSReplayOutput(addr)
	if err != nil {
		t.Fatal(err)
	}
	go out.RunOutputLoop()

	// Send a CLIENT_RESPONSE frame — should be skipped.
	dt := buildTestDnstap(dnstap.Message_CLIENT_RESPONSE, "www.example.com.", dns.TypeA, 0, nil)
	frame, err := proto.Marshal(dt)
	if err != nil {
		t.Fatal(err)
	}

	out.GetOutputChannel() <- frame

	// Wait briefly, then check that nothing was received.
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = pc.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected no packet for response message, but received one")
	}

	out.Close()
}

func TestDNSReplayOutput_ParseSpec(t *testing.T) {
	out, err := ParseOutput("dns:127.0.0.1:5353")
	if err != nil {
		t.Fatalf("ParseOutput(dns:127.0.0.1:5353): %v", err)
	}
	replay, ok := out.(*DNSReplayOutput)
	if !ok {
		t.Fatalf("expected *DNSReplayOutput, got %T", out)
	}
	if replay.target != "127.0.0.1:5353" {
		t.Errorf("expected target 127.0.0.1:5353, got %s", replay.target)
	}
}

func TestDNSReplayOutput_DefaultPort(t *testing.T) {
	out, err := newDNSReplayOutput("192.168.1.1")
	if err != nil {
		t.Fatalf("newDNSReplayOutput(192.168.1.1): %v", err)
	}
	if out.target != "192.168.1.1:53" {
		t.Errorf("expected target 192.168.1.1:53, got %s", out.target)
	}
}
