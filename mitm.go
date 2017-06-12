package main

import (
	"flag"
	"fmt"
	"github.com/e0d1n/mitm/utils"
	// "github.com/google/gopacket/pcap"
)

func main() {

	devicename := flag.String("i", "en0", "Interface to listen on")
	flag.Parse()

	device, e := utils.GetInterface(*devicename)

	if e == nil {
		fmt.Println(device)
	} else {
		fmt.Println(e)
	}
}
