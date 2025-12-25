package network

import (
	"fmt"
	"net"
	"strings"
)

// finds first active non-loopback interface
func GetActiveInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		flags := iface.Flags.String()

		// skip down or loopback interfaces
		if !strings.Contains(flags, "up") || strings.Contains(flags, "loopback") {
			continue
		}

		// must have at least one ip
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		return &iface, nil
	}

	return nil, fmt.Errorf("no active interface found")
}

// returns ipv4 and subnet of interface
func GetInterfaceIP(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ipv4 := ipnet.IP.To4()
		if ipv4 == nil {
			continue
		}

		return &net.IPNet{
			IP:   ipv4,
			Mask: ipnet.Mask,
		}, nil
	}

	return nil, fmt.Errorf("no ipv4 address found on %s", iface.Name)
}
