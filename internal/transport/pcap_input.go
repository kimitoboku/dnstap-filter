package transport

import (
	"fmt"
	"os"
	"sync"

	"github.com/dnstap/golang-dnstap"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// PcapInput reads a pcap file and emits dnstap frames for each DNS packet.
type PcapInput struct {
	path string
	wg   sync.WaitGroup
}

// NewPcapInput creates a PcapInput that reads DNS packets from a pcap file.
func NewPcapInput(path string) (*PcapInput, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("pcap file: %w", err)
	}
	p := &PcapInput{path: path}
	p.wg.Add(1)
	return p, nil
}

// ReadInto reads the pcap file and sends dnstap frames to the channel.
func (p *PcapInput) ReadInto(ch chan []byte) {
	defer p.wg.Done()
	if err := p.readPcap(ch); err != nil {
		fmt.Fprintf(os.Stderr, "pcap input: %s\n", err)
	}
}

// Wait blocks until reading is complete.
func (p *PcapInput) Wait() {
	p.wg.Wait()
}

func (p *PcapInput) readPcap(ch chan []byte) error {
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create pcap reader: %w", err)
	}

	src := gopacket.NewPacketSource(reader, reader.LinkType())
	for packet := range src.Packets() {
		frame, err := packetToDnstapFrame(packet)
		if err != nil {
			continue
		}
		ch <- frame
	}
	return nil
}

// packetToDnstapFrame converts a network packet containing DNS to a
// serialized dnstap frame. Returns an error if the packet does not
// contain a DNS payload.
func packetToDnstapFrame(packet gopacket.Packet) ([]byte, error) {
	// gopacket decodes DNS on well-known ports, so ApplicationLayer
	// may be empty. Use the transport layer payload which contains
	// the raw DNS wire-format bytes.
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil, fmt.Errorf("no transport layer")
	}

	payload := transportLayer.LayerPayload()
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty transport payload")
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, fmt.Errorf("dns unpack: %w", err)
	}

	// Determine source/destination IPs.
	var srcIP, dstIP []byte
	var socketFamily dnstap.SocketFamily
	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)
		srcIP = ip.SrcIP.To4()
		dstIP = ip.DstIP.To4()
		socketFamily = dnstap.SocketFamily_INET
	} else if ipv6 := packet.Layer(layers.LayerTypeIPv6); ipv6 != nil {
		ip := ipv6.(*layers.IPv6)
		srcIP = ip.SrcIP.To16()
		dstIP = ip.DstIP.To16()
		socketFamily = dnstap.SocketFamily_INET6
	} else {
		return nil, fmt.Errorf("no IP layer")
	}

	// Determine transport protocol and ports.
	var srcPort, dstPort uint32
	var socketProto dnstap.SocketProtocol
	if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		srcPort = uint32(u.SrcPort)
		dstPort = uint32(u.DstPort)
		socketProto = dnstap.SocketProtocol_UDP
	} else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		srcPort = uint32(t.SrcPort)
		dstPort = uint32(t.DstPort)
		socketProto = dnstap.SocketProtocol_TCP
	} else {
		return nil, fmt.Errorf("no UDP/TCP layer")
	}

	ts := packet.Metadata().Timestamp
	sec := uint64(ts.Unix())
	nsec := uint32(ts.Nanosecond())

	dtType := dnstap.Dnstap_MESSAGE
	dtMsg := &dnstap.Message{
		SocketFamily:   &socketFamily,
		SocketProtocol: &socketProto,
	}

	if !msg.Response {
		// Query (QR=0) -> CLIENT_QUERY
		msgType := dnstap.Message_CLIENT_QUERY
		dtMsg.Type = &msgType
		dtMsg.QueryAddress = srcIP
		dtMsg.QueryPort = &srcPort
		dtMsg.QueryMessage = payload
		dtMsg.ResponseMessage = payload
		dtMsg.QueryTimeSec = &sec
		dtMsg.QueryTimeNsec = &nsec
	} else {
		// Response (QR=1) -> CLIENT_RESPONSE
		msgType := dnstap.Message_CLIENT_RESPONSE
		dtMsg.Type = &msgType
		dtMsg.QueryAddress = dstIP
		dtMsg.QueryPort = &dstPort
		dtMsg.ResponseAddress = srcIP
		dtMsg.ResponsePort = &srcPort
		dtMsg.QueryMessage = payload
		dtMsg.ResponseMessage = payload
		dtMsg.ResponseTimeSec = &sec
		dtMsg.ResponseTimeNsec = &nsec
	}

	dt := &dnstap.Dnstap{
		Type:    &dtType,
		Message: dtMsg,
	}
	return proto.Marshal(dt)
}
