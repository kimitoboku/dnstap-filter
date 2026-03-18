package transport

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/dnstap/golang-dnstap"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// writeDNSPcap creates a pcap file with the given DNS packets.
func writeDNSPcap(t *testing.T, path string, packets []dnsPacketSpec) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	for _, spec := range packets {
		raw, err := spec.msg.Pack()
		if err != nil {
			t.Fatalf("dns pack: %v", err)
		}

		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    spec.srcIP,
			DstIP:    spec.dstIP,
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(spec.srcPort),
			DstPort: layers.UDPPort(spec.dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(raw)); err != nil {
			t.Fatalf("serialize: %v", err)
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     spec.ts,
			CaptureLength: len(buf.Bytes()),
			Length:        len(buf.Bytes()),
		}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
}

type dnsPacketSpec struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	ts      time.Time
	msg     dns.Msg
}

func TestPcapInput_QueryAndResponse(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "test.pcap")

	queryTime := time.Date(2024, 1, 15, 10, 30, 0, 123456000, time.UTC)
	respTime := queryTime.Add(5 * time.Millisecond)

	query := dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 1234

	resp := dns.Msg{}
	resp.SetReply(&query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34"),
	})

	writeDNSPcap(t, pcapPath, []dnsPacketSpec{
		{
			srcIP: net.ParseIP("192.168.1.100"), dstIP: net.ParseIP("8.8.8.8"),
			srcPort: 12345, dstPort: 53,
			ts: queryTime, msg: query,
		},
		{
			srcIP: net.ParseIP("8.8.8.8"), dstIP: net.ParseIP("192.168.1.100"),
			srcPort: 53, dstPort: 12345,
			ts: respTime, msg: resp,
		},
	})

	input, err := NewPcapInput(pcapPath)
	if err != nil {
		t.Fatalf("NewPcapInput: %v", err)
	}

	ch := make(chan []byte, 16)
	go input.ReadInto(ch)
	input.Wait()
	close(ch)

	var frames [][]byte
	for frame := range ch {
		frames = append(frames, frame)
	}

	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	// Verify CLIENT_QUERY frame.
	dt := &dnstap.Dnstap{}
	if err := proto.Unmarshal(frames[0], dt); err != nil {
		t.Fatalf("unmarshal frame 0: %v", err)
	}
	if *dt.Type != dnstap.Dnstap_MESSAGE {
		t.Fatalf("expected MESSAGE type")
	}
	msg := dt.Message
	if *msg.Type != dnstap.Message_CLIENT_QUERY {
		t.Errorf("expected CLIENT_QUERY, got %v", *msg.Type)
	}
	if !net.IP(msg.QueryAddress).Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("query address = %v, want 192.168.1.100", net.IP(msg.QueryAddress))
	}
	if *msg.QueryPort != 12345 {
		t.Errorf("query port = %d, want 12345", *msg.QueryPort)
	}
	if *msg.QueryTimeSec != uint64(queryTime.Unix()) {
		t.Errorf("query time sec = %d, want %d", *msg.QueryTimeSec, queryTime.Unix())
	}
	if *msg.QueryTimeNsec != uint32(queryTime.Nanosecond()) {
		t.Errorf("query time nsec = %d, want %d", *msg.QueryTimeNsec, queryTime.Nanosecond())
	}
	if *msg.SocketFamily != dnstap.SocketFamily_INET {
		t.Errorf("socket family = %v, want INET", *msg.SocketFamily)
	}
	if *msg.SocketProtocol != dnstap.SocketProtocol_UDP {
		t.Errorf("socket protocol = %v, want UDP", *msg.SocketProtocol)
	}

	// Verify the DNS query can be unpacked from QueryMessage.
	parsed := new(dns.Msg)
	if err := parsed.Unpack(msg.QueryMessage); err != nil {
		t.Fatalf("unpack query message: %v", err)
	}
	if parsed.Question[0].Name != "example.com." {
		t.Errorf("query name = %s, want example.com.", parsed.Question[0].Name)
	}

	// Verify CLIENT_RESPONSE frame.
	dt2 := &dnstap.Dnstap{}
	if err := proto.Unmarshal(frames[1], dt2); err != nil {
		t.Fatalf("unmarshal frame 1: %v", err)
	}
	msg2 := dt2.Message
	if *msg2.Type != dnstap.Message_CLIENT_RESPONSE {
		t.Errorf("expected CLIENT_RESPONSE, got %v", *msg2.Type)
	}
	// CLIENT_RESPONSE: QueryAddress should be the destination (client) IP.
	if !net.IP(msg2.QueryAddress).Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("response query address = %v, want 192.168.1.100", net.IP(msg2.QueryAddress))
	}
	if *msg2.ResponseTimeSec != uint64(respTime.Unix()) {
		t.Errorf("response time sec = %d, want %d", *msg2.ResponseTimeSec, respTime.Unix())
	}

	// Verify the DNS response can be unpacked from ResponseMessage.
	parsedResp := new(dns.Msg)
	if err := parsedResp.Unpack(msg2.ResponseMessage); err != nil {
		t.Fatalf("unpack response message: %v", err)
	}
	if !parsedResp.Response {
		t.Error("expected response flag to be set")
	}
}

func TestPcapInput_FileNotFound(t *testing.T) {
	_, err := NewPcapInput("/nonexistent/test.pcap")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestPcapInput_IPv6(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "ipv6.pcap")

	query := dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAAAA)

	// Build IPv6 pcap manually.
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	raw, _ := query.Pack()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:4860:4860::8888"),
	}
	udp := &layers.UDP{SrcPort: 54321, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload(raw)); err != nil {
		t.Fatal(err)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}
	if err := w.WritePacket(ci, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.Close()

	input, err := NewPcapInput(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan []byte, 16)
	go input.ReadInto(ch)
	input.Wait()
	close(ch)

	var frames [][]byte
	for frame := range ch {
		frames = append(frames, frame)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}

	dt := &dnstap.Dnstap{}
	if err := proto.Unmarshal(frames[0], dt); err != nil {
		t.Fatal(err)
	}
	if *dt.Message.SocketFamily != dnstap.SocketFamily_INET6 {
		t.Errorf("socket family = %v, want INET6", *dt.Message.SocketFamily)
	}
	if !net.IP(dt.Message.QueryAddress).Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("query address = %v, want 2001:db8::1", net.IP(dt.Message.QueryAddress))
	}
}

// readAllFrames reads a pcap file through PcapInput and returns all dnstap frames.
func readAllFrames(t *testing.T, path string) []*dnstap.Dnstap {
	t.Helper()
	input, err := NewPcapInput(path)
	if err != nil {
		t.Fatalf("NewPcapInput(%s): %v", path, err)
	}
	ch := make(chan []byte, 32)
	go input.ReadInto(ch)
	input.Wait()
	close(ch)

	var results []*dnstap.Dnstap
	for frame := range ch {
		dt := &dnstap.Dnstap{}
		if err := proto.Unmarshal(frame, dt); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		results = append(results, dt)
	}
	return results
}

// examplePcapPath returns the path to example/dns_test.pcap relative to the
// repository root. It skips the test if the file is not found.
func examplePcapPath(t *testing.T) string {
	t.Helper()
	// The test binary runs from the package directory. Walk up to find the
	// repository root containing the example/ directory.
	candidates := []string{
		"../../example/dns_test.pcap",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("example/dns_test.pcap not found; skipping")
	return ""
}

func TestExamplePcap_FrameCount(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	// example/dns_test.pcap contains 4 query/response pairs = 8 packets.
	if len(frames) != 8 {
		t.Fatalf("expected 8 frames, got %d", len(frames))
	}

	queries := 0
	responses := 0
	for _, dt := range frames {
		switch *dt.Message.Type {
		case dnstap.Message_CLIENT_QUERY:
			queries++
		case dnstap.Message_CLIENT_RESPONSE:
			responses++
		}
	}
	if queries != 4 {
		t.Errorf("expected 4 CLIENT_QUERY, got %d", queries)
	}
	if responses != 4 {
		t.Errorf("expected 4 CLIENT_RESPONSE, got %d", responses)
	}
}

func TestExamplePcap_QueryNames(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	nameSet := map[string]bool{}
	for _, dt := range frames {
		msg := new(dns.Msg)
		if err := msg.Unpack(dt.Message.QueryMessage); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if len(msg.Question) > 0 {
			nameSet[msg.Question[0].Name] = true
		}
	}

	expected := []string{"example.com.", "www.google.com.", "nxdomain.example.com."}
	for _, name := range expected {
		if !nameSet[name] {
			t.Errorf("expected query name %q not found in pcap", name)
		}
	}
}

func TestExamplePcap_QueryTypes(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	typeSet := map[uint16]bool{}
	for _, dt := range frames {
		msg := new(dns.Msg)
		if err := msg.Unpack(dt.Message.QueryMessage); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if len(msg.Question) > 0 {
			typeSet[msg.Question[0].Qtype] = true
		}
	}

	if !typeSet[dns.TypeA] {
		t.Error("expected A query type in pcap")
	}
	if !typeSet[dns.TypeAAAA] {
		t.Error("expected AAAA query type in pcap")
	}
}

func TestExamplePcap_ResponseAddress(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	for _, dt := range frames {
		if *dt.Message.Type != dnstap.Message_CLIENT_RESPONSE {
			continue
		}
		if dt.Message.ResponseAddress == nil {
			t.Error("CLIENT_RESPONSE has nil ResponseAddress")
		}
		if dt.Message.QueryAddress == nil {
			t.Error("CLIENT_RESPONSE has nil QueryAddress")
		}
	}
}

func TestExamplePcap_ClientIPs(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	ipSet := map[string]bool{}
	for _, dt := range frames {
		if dt.Message.QueryAddress != nil {
			ipSet[net.IP(dt.Message.QueryAddress).String()] = true
		}
	}

	// The example pcap has clients 192.168.1.100 and 10.0.0.50.
	if !ipSet["192.168.1.100"] {
		t.Error("expected client IP 192.168.1.100")
	}
	if !ipSet["10.0.0.50"] {
		t.Error("expected client IP 10.0.0.50")
	}
}

func TestExamplePcap_NXDOMAINResponse(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	found := false
	for _, dt := range frames {
		if *dt.Message.Type != dnstap.Message_CLIENT_RESPONSE {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(dt.Message.ResponseMessage); err != nil {
			continue
		}
		if msg.Rcode == dns.RcodeNameError {
			found = true
			// Verify the NXDOMAIN is for the expected query name.
			if len(msg.Question) > 0 && msg.Question[0].Name != "nxdomain.example.com." {
				t.Errorf("NXDOMAIN query name = %s, want nxdomain.example.com.", msg.Question[0].Name)
			}
		}
	}
	if !found {
		t.Error("expected NXDOMAIN response in pcap")
	}
}

func TestExamplePcap_Timestamps(t *testing.T) {
	path := examplePcapPath(t)
	frames := readAllFrames(t, path)

	type ts struct {
		sec  uint64
		nsec uint32
	}

	// Collect all timestamps and verify they are monotonically non-decreasing.
	var timestamps []ts
	for _, dt := range frames {
		msg := dt.Message
		if msg.QueryTimeSec != nil {
			nsec := uint32(0)
			if msg.QueryTimeNsec != nil {
				nsec = *msg.QueryTimeNsec
			}
			timestamps = append(timestamps, ts{*msg.QueryTimeSec, nsec})
		} else if msg.ResponseTimeSec != nil {
			nsec := uint32(0)
			if msg.ResponseTimeNsec != nil {
				nsec = *msg.ResponseTimeNsec
			}
			timestamps = append(timestamps, ts{*msg.ResponseTimeSec, nsec})
		}
	}

	if !sort.SliceIsSorted(timestamps, func(i, j int) bool {
		if timestamps[i].sec != timestamps[j].sec {
			return timestamps[i].sec < timestamps[j].sec
		}
		return timestamps[i].nsec <= timestamps[j].nsec
	}) {
		t.Errorf("timestamps are not monotonically non-decreasing: %v", timestamps)
	}
}
