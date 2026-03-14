package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/kimitoboku/dnstap-filter/internal/expression"
	"github.com/kimitoboku/dnstap-filter/internal/filter"
	"github.com/kimitoboku/dnstap-filter/internal/transport"
)

type cliConfig struct {
	inputSpec       string
	outputSpec      string
	filterExpr      string
	printFilterTree bool
	countLimit      int
}

func parseCLIArgs(args []string) (cliConfig, error) {
	fs := flag.NewFlagSet("dnstap-filter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	in := fs.String("in", "", "input spec: file:<path> | unix:<path> | tcp:<host:port>")
	out := fs.String("out", "", "output spec: file:<path> | unix:<path> | tcp:<host:port> | yaml:<path>|yaml:-\n\t(default: print query name, type and time to stdout)")
	filterExpr := fs.String("filter", "", "filter expression, e.g. 'ip=1.1.1.1 and (suffix=example.com. or rcode=NXDOMAIN)'")
	printFilterTree := fs.Bool("print-filter-tree", false, "print parsed filter expression tree and exit")
	countLimit := 0
	fs.IntVar(&countLimit, "cout", 0, "process only the first N records from input")
	fs.IntVar(&countLimit, "c", 0, "shorthand of --cout")

	if err := fs.Parse(args); err != nil {
		return cliConfig{}, err
	}
	if fs.NArg() > 0 {
		return cliConfig{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if countLimit < 0 {
		return cliConfig{}, fmt.Errorf("flag --cout/-c must be >= 0")
	}
	if !*printFilterTree && *in == "" {
		return cliConfig{}, fmt.Errorf("required flag: --in (or use --print-filter-tree)")
	}

	return cliConfig{
		inputSpec:       *in,
		outputSpec:      *out,
		filterExpr:      *filterExpr,
		printFilterTree: *printFilterTree,
		countLimit:      countLimit,
	}, nil
}

func dnstapFilter(outputChannel chan []byte, root filter.Node, countLimit int) (chan []byte, chan struct{}) {
	inputChannel := make(chan []byte, 32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dt := &dnstap.Dnstap{}
		processed := 0
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
				if !root.Eval(*dt.Message) {
					continue
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

	o, err := transport.ParseOutput(cfg.outputSpec)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	go o.RunOutputLoop()
	outputChannel := o.GetOutputChannel()

	inputChannel, filterDone := dnstapFilter(outputChannel, root, cfg.countLimit)
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
