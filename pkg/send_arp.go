package pkg

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SendARP(handle *pcap.Handle, iface *net.Interface, ipnet *net.IPNet, eth *layers.Ethernet, ip net.IP) {

	// construct arp layer
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: ipnet.IP,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    ip,
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, options, eth, arp)
	if err != nil {
		log.Fatalf("Failed to serialize packet: %v", err)
	}
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to write packet: %v", err)
	}

}
