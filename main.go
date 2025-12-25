package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/faiyaz032/arp-scanner/pkg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = 1 * time.Second
)

func main() {
	iface, err := pkg.GetActiveInterface()
	if err != nil {
		log.Fatalf("Failed to find active interface: %v", err)
	}
	ipnet, err := pkg.GetInterfaceIP(iface)
	if err != nil {
		log.Fatalf("Failed to find interface ip: %v", err)
	}

	usableIPs, _, _ := pkg.GenerateIPs(ipnet)

	// open live capture to capture raw bytes
	handle, err := pcap.OpenLive(iface.Name, snapshotLen, promiscuous, timeout)
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}

	if err != nil {
		log.Fatalf("Failed to open live capture: %v", err)
	}
	defer handle.Close()

	// construct ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{255, 255, 255, 255, 255, 255}, //broadcast mac
		EthernetType: layers.EthernetTypeARP,
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var mu sync.Mutex
	results := make(map[string]string)
	done := make(chan struct{})

	//goroutine to receive packets
	go func() {
		for {
			select {
			case packet, ok := <-packetSource.Packets():

				if !ok {
					return
				}

				if packet == nil {
					continue
				}

				arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
				if !ok {
					continue
				}

				if arp.Operation != layers.ARPReply {
					continue
				}

				ip := net.IP(arp.SourceProtAddress).String()
				mac := net.HardwareAddr(arp.SourceHwAddress).String()

				// avoid duplicates
				mu.Lock()
				if _, exists := results[ip]; !exists {
					results[ip] = mac
					fmt.Printf("Host found: %s → %s\n", ip, mac)
				}
				mu.Unlock()

			case <-done:
				return
			}
		}
	}()

	for _, ip := range usableIPs {
		pkg.SendARP(handle, iface, ipnet, eth, ip)
		time.Sleep(10 * time.Millisecond)
	}

	waitTime := time.Duration(len(usableIPs)/10) * time.Second
	time.Sleep(waitTime)
	close(done)
}
