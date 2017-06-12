package utils

import (
	"github.com/google/gopacket/pcap"
)

// IndexDeviceByName returns the index of the device given the name, -1 if not found
func IndexDeviceByName(devices []pcap.Interface, name string) int {
	for i, device := range devices {
		if device.Name == name {
			return i
		}
	}
	return -1
}

// IncludeDeviceByName returns `true` if the device is found, false if not
// func IncludeDeviceByName(devices []pcap.Interface, name string) bool {
//     return IncludeDeviceByName(devices, name) >= 0
// }

// Index returns the first index of the target string `t`, or // -1 if no match is found.
func Index(vs []string, t string) int {
	for i, v := range vs {
		if v == t {
			return i
		}
	}
	return -1
}

// Include returns `true` if the target string t is in the // slice.
func Include(vs []string, t string) bool {
	return Index(vs, t) >= 0
}
