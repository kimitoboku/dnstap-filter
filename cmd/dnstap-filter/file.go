package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dnstap/golang-dnstap"
)

const outputChannelSize = 32

type fileOutput struct {
	filename      string
	output        dnstap.Output
	outputChannel chan []byte
	done          chan struct{}
}

func newFileOutput(filename string) (*fileOutput, error) {
	o, err := dnstap.NewFrameStreamOutputFromFilename(filename)
	if err != nil {
		return nil, err
	}
	return &fileOutput{
		filename:      filename,
		output:        o,
		outputChannel: make(chan []byte, outputChannelSize),
		done:          make(chan struct{}),
	}, nil
}

func (p *fileOutput) GetOutputChannel() chan []byte {
	return p.outputChannel
}

func (p *fileOutput) Close() {
	close(p.outputChannel)
	<-p.done
}

func (p *fileOutput) RunOutputLoop() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGHUP)
	o := p.output
	go o.RunOutputLoop()
	defer func() {
		o.Close()
		close(p.done)
	}()
	for {
		select {
		case b, ok := <-p.outputChannel:
			if !ok {
				return
			}
			o.GetOutputChannel() <- b
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				o.Close()
				newo, err := dnstap.NewFrameStreamOutputFromFilename(p.filename)
				if err != nil {
					fmt.Fprintf(os.Stderr,
						"dnstap: Error: failed to reopen %s: %v\n",
						p.filename, err)
					os.Exit(1)
				}
				o = newo
				go o.RunOutputLoop()
				continue
			} else {
				os.Exit(0)
			}
		}
	}
}
