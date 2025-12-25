package network

import "net"

// generates all usable ips from subnet
func GenerateIPs(ipnet *net.IPNet) (
	usableIPs []net.IP,
	networkIP net.IP,
	broadcastIP net.IP,
) {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil, nil, nil
	}

	// calculate network ip
	networkIP = ip.Mask(ipnet.Mask)

	var allIPs []net.IP

	// loop through subnet
	for ip := networkIP; ipnet.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		allIPs = append(allIPs, ipCopy)
	}

	if len(allIPs) < 2 {
		return nil, networkIP, nil
	}

	// last ip is broadcast
	broadcastIP = allIPs[len(allIPs)-1]

	// remove network and broadcast
	if len(allIPs) > 2 {
		usableIPs = allIPs[1 : len(allIPs)-1]
	}

	return usableIPs, networkIP, broadcastIP
}

// increments ip by 1
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
