package utils

import (
	"net"
)

// Return a byte array containing the IPv4 address
func GetIp(ip string) []byte {
	return []byte(net.ParseIP(ip).To4())
}
