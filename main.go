package main

import (
	"fmt"
	"log"
	"net"
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

	usableIPs, networkIP, broadcastIP := pkg.GenerateIPs(ipnet)

	// open live capture to capture raw bytes
	handle, err := pcap.OpenLive(iface.Name, snapshotLen, promiscuous, timeout)
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

	// send arp requests for each usable ip
	for _, ip := range usableIPs {
		pkg.SendARP(handle, iface, ipnet, eth, ip)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// receive packets
	for packet := range packetSource.Packets() {

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

		ip := net.IP(arp.SourceProtAddress)
		mac := net.HardwareAddr(arp.SourceHwAddress)

		fmt.Printf("Host found: %s → %s\n", ip, mac)
	}

	fmt.Println("Interface Name:", iface.Name)
	fmt.Println("IP:", ipnet.IP)
	fmt.Println("IP Mask:", ipnet.Mask)
	fmt.Println("Source MAC:", iface.HardwareAddr.String())
	fmt.Println("Netowork IP: ", networkIP)
	fmt.Println("Broadcast IP: ", broadcastIP)
}
