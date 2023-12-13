package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	// var eth layers.Ethernet
	// var ip4 layers.IPv4
	// var ip6 layers.IPv6
	// var tcp layers.TCP
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{
			SrcIP: net.IPv4(255, 255, 255, 0),
			DstIP: net.IPv4(190, 20, 69, 11),
			// Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(1234),
			DstPort: layers.TCPPort(443),
		},
		gopacket.Payload([]byte{1, 2, 3, 4}))
	packetData := buf.Bytes()
	fmt.Println(packetData)
}
