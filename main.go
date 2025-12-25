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

	_, networkIP, broadcastIP := pkg.GenerateIPs(ipnet)

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

	// construct arp layer
	arp := &layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,
		Operation:       layers.ARPRequest,

		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: ipnet.IP,

		DstHwAddress:   []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: []byte(net.ParseIP("192.168.0.101").To4()),
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, options, eth, arp)
	if err != nil {
		log.Fatalf("Failed to serialize packet: %v", err)
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to write packet: %v", err)
	}

	fmt.Println("Interface Name:", iface.Name)
	fmt.Println("IP:", ipnet.IP)
	fmt.Println("IP Mask:", ipnet.Mask)
	fmt.Println("Source MAC:", iface.HardwareAddr.String())
	fmt.Println("Netowork IP: ", networkIP)
	fmt.Println("Broadcast IP: ", broadcastIP)
}
