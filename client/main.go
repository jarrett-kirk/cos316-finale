package main

import (
	"COS316-FINALE/iptable"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {

	// os.Open() opens specific file in
	// read-only mode and this return
	// a pointer of type os.File
	file, err := os.Open("IP-packets.csv")

	// Checks for the error
	if err != nil {
		log.Fatal("Error while reading the file", err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()

	if err != nil {
		fmt.Println("Error reading records")
	}

	for _, eachrecord := range records {
		fmt.Println(eachrecord)
	}

	// var eth layers.Ethernet
	// var ip4 layers.IPv4
	// var ip6 layers.IPv6
	// var tcp layers.TCP
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		// &layers.Ethernet{},
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

	// Make a table and print
	filter := iptable.NewIPTable("ACCEPT")
	fmt.Println("filter ", filter)

	// Decode a packet
	packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Default)
	// Get the TCP layer from this packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	fmt.Println("tcpLayer: ", tcpLayer)
	if tcpLayer != nil {
		fmt.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	// Iterate over all layers, printing out each layer type
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
}
