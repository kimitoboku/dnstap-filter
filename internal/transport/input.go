package transport

import (
	"fmt"
	"net"

	"github.com/dnstap/golang-dnstap"
)

// ParseInput parses a transport spec and returns a dnstap.Input.
//
// Supported schemes:
//   - file:<path>      - dnstap frame stream file
//   - unix:<path>      - Unix domain socket server (listens for incoming connections)
//   - tcp:<host:port>  - TCP server (listens for incoming connections)
//   - pcap:<path>      - pcap file (DNS packets converted to dnstap)
//
// Bare paths without a scheme are treated as file: (backward compatibility).
func ParseInput(spec string) (dnstap.Input, error) {
	u, err := parseURI(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid input spec %q: %w", spec, err)
	}

	switch u.scheme {
	case schemeFile:
		return dnstap.NewFrameStreamInputFromFilename(u.address)
	case schemeUnix:
		i, err := dnstap.NewFrameStreamSockInputFromPath(u.address)
		if err != nil {
			return nil, fmt.Errorf("unix input: failed to listen on %s: %w", u.address, err)
		}
		return i, nil
	case schemeTCP:
		listener, err := net.Listen("tcp", u.address)
		if err != nil {
			return nil, fmt.Errorf("tcp input: failed to listen on %s: %w", u.address, err)
		}
		return dnstap.NewFrameStreamSockInput(listener), nil
	case schemePcap:
		return NewPcapInput(u.address)
	default:
		return nil, fmt.Errorf("unsupported input scheme %q", u.scheme)
	}
}
