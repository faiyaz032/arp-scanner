package arp

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// listens for arp replies
func ListenARPReplies(
	handle *pcap.Handle,
	results map[string]string,
	mu *sync.Mutex,
	done <-chan struct{},
) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case packet, ok := <-packetSource.Packets():
			if !ok || packet == nil {
				continue
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp, ok := arpLayer.(*layers.ARP)
			if !ok || arp.Operation != layers.ARPReply {
				continue
			}

			ip := net.IP(arp.SourceProtAddress).String()
			mac := net.HardwareAddr(arp.SourceHwAddress).String()

			mu.Lock()
			if _, exists := results[ip]; !exists {
				results[ip] = mac
				fmt.Printf("host found: %s -> %s\n", ip, mac)
			}
			mu.Unlock()

		case <-done:
			return
		}
	}
}
