package main

import (
	"flag"
	"fmt"
	"github.com/e0d1n/mitm/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"time"
)

func main() {

	var err error
	var handle *pcap.Handle

	i := flag.String("i", "en0", "Interface to listen on")
	p := flag.Bool("p", true, "Promiscuous listening")
	l := flag.Int("l", 1024, "Len of packets")
	t := flag.Int("t", -1, "Timeout")
	flag.Parse()

	devicename := *i
	promiscuous := *p
	snapshot_len := *l
	timeout := time.Duration(*t) * time.Second

	// Return the device
	device, e := utils.GetInterface(devicename)
	if e == nil {
		fmt.Println(device)
	} else {
		fmt.Println(e)
		os.Exit(1)
	}

	// Open handler
	handle, err = pcap.OpenLive(devicename, int32(snapshot_len), promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	// Remember to close the handle
	defer handle.Close()

	// Create a properly formed packet, just with
	// empty details. Should fill out MAC addresses,
	// IP addresses, etc.
	var (
		buffer  gopacket.SerializeBuffer
		options gopacket.SerializeOptions
	)

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
		DstMAC:       net.HardwareAddr{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:        0x1,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   0x6,
		ProtAddressSize: 0x4,
		// Request 1, Reply 2
		Operation:         0x2,
		SourceHwAddress:   []byte{},
		SourceProtAddress: []byte{},
		DstHwAddress:      []byte{},
		DstProtAddress:    []byte{},
	}
	// Create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		arpLayer,
	)
	outgoingPacket := buffer.Bytes()

	// Send the packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
