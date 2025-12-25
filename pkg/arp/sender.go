package arp

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sends one arp request packet
func SendARP(
	handle *pcap.Handle,
	iface *net.Interface,
	ipnet *net.IPNet,
	targetIP net.IP,
) {
	// ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{255, 255, 255, 255, 255, 255},
		EthernetType: layers.EthernetTypeARP,
	}

	// arp layer
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: ipnet.IP,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, eth, arp); err != nil {
		log.Fatalf("failed to serialize arp packet: %v", err)
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatalf("failed to send arp packet: %v", err)
	}
}
