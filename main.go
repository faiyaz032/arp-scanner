package main

import (
	"fmt"
	"log"
	"time"

	"github.com/faiyaz032/arp-scanner/pkg"
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

	fmt.Println("Interface Name:", iface.Name)
	fmt.Println("IP:", ipnet.IP)
	fmt.Println("IP Mask:", ipnet.Mask)
	fmt.Println("Source MAC:", iface.HardwareAddr.String())
	fmt.Println("Netowork IP: ", networkIP)
	fmt.Println("Broadcast IP: ", broadcastIP)
	fmt.Println("Usable IPs: ", usableIPs)
}
