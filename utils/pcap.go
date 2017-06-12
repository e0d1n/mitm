package utils

import (
	"fmt"
	"github.com/google/gopacket/pcap"
)

// HasInterface returns the index of the interface if exists, -1 otherwise
func HasInterface(devices []pcap.Interface, name string) int {
	return IndexDeviceByName(devices, name)
}

// GetInterface returns the Interface device with the specified name
func GetInterface(name string) (pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	index := HasInterface(devices, name)
	if index == -1 {
		return pcap.Interface{}, fmt.Errorf("Interface %s not found", name)
	}
	return devices[index], nil
}
