package main

import (
	"fmt"
	"os"

	"github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/kimitoboku/dnstap-filter/filters"
)

func dnstapFilter(outputChannel chan []byte, filterList []filters.DnstapFilterFunc) chan []byte {
	inputChannel := make(chan []byte, 32)
	go func() {
		dt := &dnstap.Dnstap{}
		for frame := range inputChannel {
			if err := proto.Unmarshal(frame, dt); err != nil {
				fmt.Printf("dnstap.TextOutput: proto.Unmarshal() failed: %s, returning", err)
				break
			}
			if *dt.Type == dnstap.Dnstap_MESSAGE {
				m := dt.Message

				drop := false
				for _, filter := range filterList {
					check := filter.Filter(*m)
					if !check {
						drop = true
					}
				}
				if drop {
					continue
				}
			}
			outputChannel <- frame
		}
	}()

	return inputChannel
}

func main() {
	inputFileName := os.Args[1]
	outputFileName := os.Args[2]
	filterIP := os.Args[3]
	i, err := dnstap.NewFrameStreamInputFromFilename(inputFileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file %s: %v\n", inputFileName, err)
	}

	o, err := newFileOutput(outputFileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: File output error on '%s': %v\n",
			outputFileName, err)
		os.Exit(1)
	}
	go o.RunOutputLoop()
	outputChannel := o.GetOutputChannel()

	var filterList []filters.DnstapFilterFunc
	ipFilter := filters.NewIPFilter(filterIP)
	filterList = append(filterList, ipFilter)

	inputChannel := dnstapFilter(outputChannel, filterList)
	go i.ReadInto(inputChannel)

	i.Wait()
}
