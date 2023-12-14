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
	fmt.Println("Target: ", target)
	filter.AddRule("INPUT", "testRule", "192.168.3.14", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "DROP")
	// target = filter.TraverseChains(records[84])  // should ACCEPT
	target = filter.TraverseChains(records[1]) // should DROP
	fmt.Println("Target: ", target)
	filter.DeleteRule("INPUT", "testRule")
	target = filter.TraverseChains(records[1]) // should ACCEPT again now that rule is deleted
	fmt.Println("Target: ", target)

}
