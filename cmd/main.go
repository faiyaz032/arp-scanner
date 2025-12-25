package main

import (
	"log"
	"sync"
	"time"

	"github.com/faiyaz032/arp-scanner/pkg/arp"
	network "github.com/faiyaz032/arp-scanner/pkg/netowork"

	"github.com/google/gopacket/pcap"
)

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = 1 * time.Second
)

func main() {
	// get active interface
	iface, err := network.GetActiveInterface()
	if err != nil {
		log.Fatalf("failed to find active interface: %v", err)
	}

	// get interface ip and subnet
	ipnet, err := network.GetInterfaceIP(iface)
	if err != nil {
		log.Fatalf("failed to get interface ip: %v", err)
	}

	// generate all usable ips
	usableIPs, _, _ := network.GenerateIPs(ipnet)

	// open pcap handle
	handle, err := pcap.OpenLive(
		iface.Name,
		snapshotLen,
		promiscuous,
		timeout,
	)
	if err != nil {
		log.Fatalf("failed to open live capture: %v", err)
	}
	defer handle.Close()

	// capture only arp packets
	if err := handle.SetBPFFilter("arp"); err != nil {
		log.Fatalf("failed to set bpf filter: %v", err)
	}

	results := make(map[string]string)
	var mu sync.Mutex
	done := make(chan struct{})

	// start arp reply listener
	go arp.ListenARPReplies(handle, results, &mu, done)

	// send arp request to all ips
	for _, ip := range usableIPs {
		arp.SendARP(handle, iface, ipnet, ip)
		time.Sleep(10 * time.Millisecond)
	}

	// wait some time for replies
	waitTime := time.Duration(len(usableIPs)/10) * time.Second
	time.Sleep(waitTime)
	close(done)
}
