package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/kimitoboku/dnstap-filter/internal/expression"
	"github.com/kimitoboku/dnstap-filter/internal/filter"
	"github.com/kimitoboku/dnstap-filter/internal/transport"
)

// stringSlice implements flag.Value so that --out can be specified multiple times.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

type cliConfig struct {
	inputSpec       string
	outputSpecs     []string
	filterExpr      string
	printFilterTree bool
	countLimit      int
	speed           float64
}

func parseCLIArgs(args []string) (cliConfig, error) {
	fs := flag.NewFlagSet("dnstap-filter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	in := fs.String("in", "", "input spec: file:<path> | unix:<path> | tcp:<host:port> | pcap:<path> | device:<iface>")
	var outSpecs stringSlice
	fs.Var(&outSpecs, "out", "output spec (repeatable): file:<path> | unix:<path> | tcp:<host:port> | yaml:<path>|yaml:- | jsonl:<path>|jsonl:-\n"+
		"\tstdout:<fields> - customizable stdout (comma-separated fields)\n"+
		"\t  fields: time, qr, msgtype, name, type, rcode, ip\n"+
		"\t  example: stdout:time,qr,name,type,rcode\n"+
		"\tdns:<host:port> - replay DNS queries to target server (UDP, fire-and-forget)\n"+
		"\t  example: dns:8.8.8.8:53\n"+
		"\t(can be specified multiple times for fan-out to multiple destinations)\n"+
		"\t(default: print \"<time> <Q|R> <name> <type> [<rcode>]\" to stdout)")
	filterExpr := fs.String("filter", "", "filter expression (omit to match all)\n"+
		"\tPredicates:\n"+
		"\t  ip=<addr>               IP match (src or dst)            ip=1.1.1.1\n"+
		"\t  src.ip=<addr>           query source IP only             src.ip=1.1.1.1\n"+
		"\t  dst.ip=<addr>           response dest IP only            dst.ip=10.0.0.1\n"+
		"\t  subnet=<CIDR>          subnet match (src or dst)        subnet=192.168.0.0/24\n"+
		"\t  src.subnet=<CIDR>      query source subnet only         src.subnet=10.0.0.0/8\n"+
		"\t  dst.subnet=<CIDR>      response dest subnet only        dst.subnet=172.16.0.0/12\n"+
		"\t  port=<number>          port match (src or dst)          port=53\n"+
		"\t  src.port=<number>      query source port only           src.port=12345\n"+
		"\t  dst.port=<number>      response dest port only          dst.port=53\n"+
		"\t  fqdn=<name>            query name exact match (FQDN)    fqdn=www.example.com.\n"+
		"\t  suffix=<suffix>        query name suffix match          suffix=example.com.\n"+
		"\t  qtype=<type>           DNS query type                   qtype=AAAA\n"+
		"\t  rcode=<rcode>          DNS response code                rcode=NXDOMAIN\n"+
		"\t  rdata=<value>          response answer record data:\n"+
		"\t    <IP>                   A/AAAA exact match             rdata=93.184.216.34\n"+
		"\t    <CIDR>                 A/AAAA subnet match            rdata=10.0.0.0/8\n"+
		"\t    <string>               TXT substring match            rdata=v=spf1\n"+
		"\t  regexp=<pattern>       query name regexp match          regexp=\\.example\\.com\\.$\n"+
		"\t  msgtype=<type>         dnstap message type              msgtype=CLIENT_QUERY\n"+
		"\t    types: CLIENT_QUERY CLIENT_RESPONSE RESOLVER_QUERY RESOLVER_RESPONSE\n"+
		"\t           AUTH_QUERY AUTH_RESPONSE FORWARDER_QUERY FORWARDER_RESPONSE\n"+
		"\t  time.after=<time>      messages at or after time        time.after=2024-01-01T00:00:00Z\n"+
		"\t  time.before=<time>     messages before time             time.before=2024-01-02T00:00:00Z\n"+
		"\t    time formats: RFC3339 (2024-01-01T00:00:00Z) or Unix epoch seconds (1704067200)\n"+
		"\tLogical operators: and  or  not  (...)\n"+
		"\tExample: 'src.subnet=192.168.0.0/24 and (qtype=AAAA or rcode=NXDOMAIN)'")
	printFilterTree := fs.Bool("print-filter-tree", false, "print parsed filter expression tree and exit")
	countLimit := 0
	fs.IntVar(&countLimit, "cout", 0, "process only the first N records from input")
	fs.IntVar(&countLimit, "c", 0, "shorthand of --cout")
	speed := fs.Float64("speed", 0, "output pacing based on dnstap timestamps (default 0 = max speed)\n"+
		"\t0 = max speed (no delay)\n"+
		"\t1 = realtime (original timestamp intervals)\n"+
		"\t2 = 2x speed (half the delay), 0.5 = half speed (double the delay)")

	if err := fs.Parse(args); err != nil {
		return cliConfig{}, err
	}
	if fs.NArg() > 0 {
		return cliConfig{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if countLimit < 0 {
		return cliConfig{}, fmt.Errorf("flag --cout/-c must be >= 0")
	}
	if *speed < 0 {
		return cliConfig{}, fmt.Errorf("flag --speed must be >= 0")
	}
	if !*printFilterTree && *in == "" {
		return cliConfig{}, fmt.Errorf("required flag: --in (or use --print-filter-tree)")
	}

	return cliConfig{
		inputSpec:       *in,
		outputSpecs:     []string(outSpecs),
		filterExpr:      *filterExpr,
		printFilterTree: *printFilterTree,
		countLimit:      countLimit,
		speed:           *speed,
	}, nil
}

func dnstapFilter(outputChannel chan []byte, root filter.Node, countLimit int, speed float64) (chan []byte, chan struct{}) {
	inputChannel := make(chan []byte, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := &dnstap.Dnstap{}
		ctx := filter.NewEvalContext()
		processed := 0
		var prevTime time.Time
		var hasPrev bool
		for frame := range inputChannel {
			if countLimit > 0 && processed >= countLimit {
				continue
			}
			processed++

			if err := proto.Unmarshal(frame, dt); err != nil {
				fmt.Printf("dnstap.TextOutput: proto.Unmarshal() failed: %s, returning", err)
				break
			}
			if dt.Type != nil && *dt.Type == dnstap.Dnstap_MESSAGE && dt.Message != nil {
				ctx.Reset()
				if !root.Eval(dt.Message, ctx) {
					continue
				}
				if speed > 0 {
					if t, ok := filter.MessageTime(dt.Message); ok {
						if hasPrev && t.After(prevTime) {
							delay := time.Duration(float64(t.Sub(prevTime)) / speed)
							time.Sleep(delay)
						}
						prevTime = t
						hasPrev = true
					}
				}
			}
			outputChannel <- frame
		}
	}()

	return inputChannel, done
}

func run(args []string) error {
	cfg, err := parseCLIArgs(args)
	if err != nil {
		return err
	}

	root, err := expression.ParseFilterExpression(cfg.filterExpr)
	if err != nil {
		return fmt.Errorf("invalid filter expression: %w", err)
	}
	if cfg.printFilterTree {
		fmt.Println(filter.FormatTree(root))
		return nil
	}

	i, err := transport.ParseInput(cfg.inputSpec)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}

	o, err := transport.ParseOutputs(cfg.outputSpecs)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	go o.RunOutputLoop()
	outputChannel := o.GetOutputChannel()

	inputChannel, filterDone := dnstapFilter(outputChannel, root, cfg.countLimit, cfg.speed)
	go i.ReadInto(inputChannel)
	i.Wait()
	close(inputChannel)
	<-filterDone
	o.Close()

	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
