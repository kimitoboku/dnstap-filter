package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/kimitoboku/dnstap-filter/filters"
)

type cliConfig struct {
	inputFileName  string
	outputFileName string
	filterExpr     string
}

func parseCLIArgs(args []string) (cliConfig, error) {
	fs := flag.NewFlagSet("dnstap-filter", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	in := fs.String("in", "", "input dnstap file")
	out := fs.String("out", "", "output dnstap file")
	filterExpr := fs.String("filter", "", "filter expression, e.g. 'ip=1.1.1.1 and (suffix=example.com. or rcode=NXDOMAIN)'")

	if err := fs.Parse(args); err != nil {
		return cliConfig{}, err
	}
	if fs.NArg() > 0 {
		return cliConfig{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if *in == "" || *out == "" || *filterExpr == "" {
		return cliConfig{}, errors.New("required flags: --in, --out, --filter")
	}

	return cliConfig{
		inputFileName:  *in,
		outputFileName: *out,
		filterExpr:     *filterExpr,
	}, nil
}

func dnstapFilter(outputChannel chan []byte, root filters.Node) chan []byte {
	inputChannel := make(chan []byte, 32)
	go func() {
		dt := &dnstap.Dnstap{}
		for frame := range inputChannel {
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

	return inputChannel
}

func run(args []string) error {
	cfg, err := parseCLIArgs(args)
	if err != nil {
		return err
	}

	root, err := filters.ParseFilterExpression(cfg.filterExpr)
	if err != nil {
		return fmt.Errorf("invalid filter expression: %w", err)
	}

	i, err := dnstap.NewFrameStreamInputFromFilename(cfg.inputFileName)
	if err != nil {
		return fmt.Errorf("dnstap: failed to open input file %s: %v", cfg.inputFileName, err)
	}

	o, err := newFileOutput(cfg.outputFileName)
	if err != nil {
		return fmt.Errorf("dnstap: file output error on '%s': %v", cfg.outputFileName, err)
	}
	go o.RunOutputLoop()
	outputChannel := o.GetOutputChannel()

	inputChannel := dnstapFilter(outputChannel, root)
	go i.ReadInto(inputChannel)
	i.Wait()

	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
