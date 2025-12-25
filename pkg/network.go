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

	return nil, fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}

func GenerateIPs(ipnet *net.IPNet) (
	usableIPs []net.IP,
	networkIP net.IP,
	broadcastIP net.IP,
) {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil, nil, nil
	}

	// netowrk IP
	networkIP = ip.Mask(ipnet.Mask)

	// collect all ips
	var allIPs []net.IP
	for ip := networkIP; ipnet.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		allIPs = append(allIPs, ipCopy)
	}

	if len(allIPs) < 2 {
		return nil, networkIP, nil
	}

	// broadcastIP = last IP in subnet
	broadcastIP = allIPs[len(allIPs)-1]

	// remove network & broadcast
	if len(allIPs) > 2 {
		usableIPs = allIPs[1 : len(allIPs)-1]
	}

	return usableIPs, networkIP, broadcastIP
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
