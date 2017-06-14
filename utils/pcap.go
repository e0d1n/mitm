package utils

import (
	"fmt"
	// "github.com/google/gopacket/pcap"
	"net"
)

// HasInterface returns the index of the interface if exists, -1 otherwise
func HasInterface(devices []net.Interface, name string) int {
	return IndexDeviceByName(devices, name)
}

// GetInterface returns the Interface device with the specified name
func GetInterface(name string) (net.Interface, error) {
	devices, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	index := HasInterface(devices, name)
	if index == -1 {
		return net.Interface{}, fmt.Errorf("Interface %s not found", name)
	}
	return devices[index], nil
}

func GetIPv4Hw(name string) ([]byte, []byte) {
	inter, e := GetInterface(name)
	if e != nil {
		panic(e)
	}

	addrs, _ := inter.Addrs()
	// handle err
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		// Check if the ip is an Ipv4
		if ip = ip.To4(); ip != nil {
			return ip, inter.HardwareAddr
		}
	}

	return []byte{}, []byte{}
}
