package transport

import (
	"fmt"
	"os"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// DeviceInput captures live DNS packets from a network interface and emits
// dnstap frames.
type DeviceInput struct {
	device string
	wg     sync.WaitGroup
}

// NewDeviceInput creates a DeviceInput that captures DNS packets from the
// specified network interface.
func NewDeviceInput(device string) (*DeviceInput, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	found := false
	for _, d := range devices {
		if d.Name == device {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("device %q not found", device)
	}
	p := &DeviceInput{device: device}
	p.wg.Add(1)
	return p, nil
}

// ReadInto opens a live capture on the device and sends dnstap frames to the channel.
func (d *DeviceInput) ReadInto(ch chan []byte) {
	defer d.wg.Done()
	if err := d.capture(ch); err != nil {
		fmt.Fprintf(os.Stderr, "device input: %s\n", err)
	}
}

// Wait blocks until the capture is complete.
func (d *DeviceInput) Wait() {
	d.wg.Wait()
}

func (d *DeviceInput) capture(ch chan []byte) error {
	handle, err := pcap.OpenLive(d.device, 65535, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", d.device, err)
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
