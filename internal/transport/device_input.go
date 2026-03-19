package transport

import (
	"fmt"
	"os"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// DeviceInput captures live DNS packets from one or more network interfaces
// and emits dnstap frames.
type DeviceInput struct {
	devices []string
	wg      sync.WaitGroup
}

// NewDeviceInput creates a DeviceInput that captures DNS packets from the
// specified network interface. Use "all" to capture from all available devices.
func NewDeviceInput(device string) (*DeviceInput, error) {
	allDevs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	var targets []string
	if device == "all" {
		for _, d := range allDevs {
			targets = append(targets, d.Name)
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no capture devices found")
		}
	} else {
		found := false
		for _, d := range allDevs {
			if d.Name == device {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("device %q not found", device)
		}
		targets = []string{device}
	}

	p := &DeviceInput{devices: targets}
	p.wg.Add(1)
	return p, nil
}

// ReadInto opens a live capture on each device and sends dnstap frames to the channel.
func (d *DeviceInput) ReadInto(ch chan []byte) {
	defer d.wg.Done()

	var capWg sync.WaitGroup
	for _, dev := range d.devices {
		capWg.Add(1)
		go func(name string) {
			defer capWg.Done()
			if err := captureDevice(name, ch); err != nil {
				fmt.Fprintf(os.Stderr, "device input %s: %s\n", name, err)
			}
		}(dev)
	}
	capWg.Wait()
}

// Wait blocks until the capture is complete.
func (d *DeviceInput) Wait() {
	d.wg.Wait()
}

func captureDevice(device string, ch chan []byte) error {
	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", device, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 53 or tcp port 53"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		frame, err := packetToDnstapFrame(packet)
		if err != nil {
			continue
		}
		ch <- frame
	}
	return nil
}
