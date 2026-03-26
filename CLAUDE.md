# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

dnstap-filter is a Go CLI tool that reads DNS messages from dnstap sources (files, sockets, pcap, live interfaces), applies filter expressions, and writes matched records to various outputs. It supports fan-out to multiple simultaneous outputs.

## Build & Test Commands

```sh
make build          # Build binary (./dnstap-filter)
make test           # Run all tests
make fmt            # Format Go files
make vet            # Run go vet
go test ./internal/filter/   # Run tests for a single package
```

Build dependency: `libpcap-dev` (Linux) or `libpcap` (macOS) is required for the `device:` input scheme (cgo).

## Architecture

The codebase has three internal packages under `internal/`:

### `internal/filter` — Filter predicate tree
- `filter.go`: Defines the `Node` interface (with `Eval` method) and AST node types: `PredicateNode`, `AndNode`, `OrNode`, `NotNode`, `MatchAllNode`. Also contains `OptimizeTree` which reorders children by cost for short-circuit evaluation.
- Each predicate type is in its own file (`ip.go`, `subnet.go`, `fqdn.go`, `suffix.go`, `qtype.go`, `rcode.go`, `rdata.go`, `regexp.go`, `msgtype.go`, `port.go`, `time.go`). Each implements the `DnstapFilterFunc` interface with a `Filter(msg, ctx)` method.
- `EvalContext` caches unpacked DNS messages to avoid redundant `dns.Msg.Unpack` calls across multiple predicates evaluating the same dnstap message.
- `addr_mode.go`: Defines `AddrMode` (Both/Src/Dst) used by ip, subnet, and port filters for directional matching.

### `internal/expression` — Filter expression parser
- Recursive-descent parser that tokenizes and parses filter expressions like `"subnet=10.0.0.0/8 and (qtype=AAAA or rcode=NXDOMAIN)"` into the filter AST.
- Operator precedence: `not` > `and` > `or`, with parentheses for grouping.
- `parsePredicate` maps `key=value` tokens to the appropriate filter constructor.

### `internal/transport` — I/O layer
- `input.go` / `output.go`: Parse `scheme:address` specs into dnstap Input/Output implementations.
- `scheme.go`: URI parsing for input/output specs (file, unix, tcp, pcap, device, yaml, jsonl, stdout).
- `MultiOutput`: Fan-out wrapper that distributes frames to multiple outputs.
- `pcap_input.go` / `device_input.go`: Convert pcap/live-capture DNS packets into dnstap frames.
- `file.go`: File output with SIGHUP-based log rotation.
- `jsonl_format.go`: JSONL output formatter.

### `cmd/dnstap-filter/main.go` — CLI entry point
- Parses CLI flags, builds the filter tree via `expression.ParseFilterExpression`, sets up input/output transports, and runs the filter loop.
- The filter loop in `dnstapFilter()` reads frames from a channel, unmarshals protobuf, evaluates the filter tree, and forwards matching frames to the output channel.

## Adding a New Filter Predicate

1. Create `internal/filter/<name>.go` implementing `DnstapFilterFunc`.
2. Add a case in `internal/expression/expression.go`'s `parsePredicate` function.
3. If the predicate doesn't require DNS message unpacking, give it cost 1 in `nodeCost` (filter.go); otherwise it defaults to cost 10.
