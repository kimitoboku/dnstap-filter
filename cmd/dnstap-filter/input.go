package main

import (
	"fmt"
	"net"

	"github.com/dnstap/golang-dnstap"
)

// parseInput parses a transport spec and returns a dnstap.Input.
//
// Supported schemes:
//   - file:<path>      - dnstap frame stream file
//   - unix:<path>      - Unix domain socket server (listens for incoming connections)
//   - tcp:<host:port>  - TCP server (listens for incoming connections)
//
// Bare paths without a scheme are treated as file: (backward compatibility).
func parseInput(spec string) (dnstap.Input, error) {
	uri, err := parseTransportURI(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid input spec %q: %w", spec, err)
	}

	switch uri.scheme {
	case schemeFile:
		return dnstap.NewFrameStreamInputFromFilename(uri.address)
	case schemeUnix:
		i, err := dnstap.NewFrameStreamSockInputFromPath(uri.address)
		if err != nil {
			return nil, fmt.Errorf("unix input: failed to listen on %s: %w", uri.address, err)
		}
		return i, nil
	case schemeTCP:
		listener, err := net.Listen("tcp", uri.address)
		if err != nil {
			return nil, fmt.Errorf("tcp input: failed to listen on %s: %w", uri.address, err)
		}
		return dnstap.NewFrameStreamSockInput(listener), nil
	default:
		return nil, fmt.Errorf("unsupported input scheme %q", uri.scheme)
	}
}
