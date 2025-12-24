package pkg

import (
	"fmt"
	"net"
	"strings"
)

func GetActiveInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()

	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		flagsStr := iface.Flags.String()

		// check if the flag is up or it has any loopback
		if !strings.Contains(flagsStr, "up") || strings.Contains(flagsStr, "loopback") {
			continue
		}

		//check if there is any ip address in that interface
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		return &iface, nil
	}
	return nil, fmt.Errorf("no active interface found")
}

func GetInterfaceIP(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()

	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)

		if !ok {
			continue
		}

		// extract the ip from ipnet struct
		ip := ipnet.IP
		ipv4 := ip.To4()

		// if this is in ipv6, continue
		if ipv4 == nil {
			continue
		}

		return ip, nil
	}
}
