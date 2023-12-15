package main

import (
	"COS316-FINALE/iptable"
	"encoding/csv"
	"fmt"
	"log"

	// "net"
	"os"
)

func filterData(filter *iptable.Table, records [][]string) {
	for _, eachrecord := range records {
		if filter.TraverseChains(eachrecord) == "ACCEPT" {
			fmt.Println(eachrecord)
		}
	}
	// target := filter.TraverseChains(records[1])
	// fmt.Println(target)
}

func main() {

	// os.Open() opens specific file in
	// read-only mode and this return
	// a pointer of type os.File
	file, err := os.Open("TEST_PACKETS1.csv")

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

	// Things to test:
	// 1. Create a default table with ACCEPT policy, send a bunch of stuff through, all accepts
	// 2. Create a rule on INPUT ipSource, send a bunch of stuff through, only matching accepts
	// 3. Create a rule on INPUT protocol == TCP with a specific port, only matching get throughconst
	// 4. Delete the ipSource rule
	// 5. Create a user chain
	// 6. Add a rule to INPUT to jump to our user chain if destip == something, send a bunch of stuff through
	mainFilter := iptable.NewIPTable("DROP")

	mainFilter.AddRule("INPUT", "protocolRule", "ANYVAL", "ANYVAL", "443", "ANYVAL", "TCP", "ANYVAL", "ACCEPT")

	// mainFilter.AddUserChain("userChain")
	// mainFilter.AddRule("INPUT", "ipRule", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "userChain")
	// mainFilter.AddRule("userChain", "ipRule", "192.168.3.13", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ACCEPT")
	// mainFilter.AddRule("userChain", "ipRule", "192.168.3.14", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ACCEPT")

	filterData(mainFilter, records)
	fmt.Println("----------------------------")
	fmt.Println("Above are all records that got through the firewall!")
}
