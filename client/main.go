package main

import (
	"COS316-FINALE/iptable"
	"encoding/csv"
	"fmt"
	"log"

	// "net"
	"os"
)

func main() {

	// os.Open() opens specific file in
	// read-only mode and this return
	// a pointer of type os.File
	file, err := os.Open("IP-packet.csv")

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

	// for loop we could use to pass each packet in records to traverse chain
	/*
		for _, eachrecord := range records {

			fmt.Println(eachrecord)
		}
	*/

	// Make a table and print
	filter := iptable.NewIPTable("ACCEPT")
	fmt.Println("filter ", filter)
	target := filter.TraverseChains(records[1])
	filter.AddRule("INPUT", "testRule", "192.168.3.14", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "DROP")
	// target = filter.TraverseChains(records[84])  // should ACCEPT
	target = filter.TraverseChains(records[1]) // should DROP
	fmt.Println("Should be DROP: ", target)
	filter.DeleteRule("INPUT", "testRule")
	target = filter.TraverseChains(records[1]) // should ACCEPT again now that rule is deleted
	fmt.Println("Should be ACCEPT: ", target)

	fmt.Println("----------------------------")

	// JARRETT TESTING AREA
	jarFilter := iptable.NewIPTable("ACCEPT")
	// add a user chain and connect it to INPUT
	jarFilter.AddChain("myChain", "ANYVAL")
	jarFilter.AddRule("INPUT", "myJumpRule", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "myChain")
	jarTarget := jarFilter.TraverseChains(records[1])
	fmt.Println("Target: ", jarTarget)

}
