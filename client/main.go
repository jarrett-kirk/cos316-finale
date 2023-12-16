package main

import (
	"COS316-FINALE/iptable"
	"encoding/csv"
	"fmt"
	"log"

	// "net"
	"os"
)

func filterData(filter *iptable.Table, records [][]string) int {
	counter := 0
	for _, eachrecord := range records {
		if filter.TraverseChains(eachrecord) == "ACCEPT" {
			fmt.Println(eachrecord)
			counter++
		}
	}
	return counter
	// target := filter.TraverseChains(records[1])
	// fmt.Println(target)
}

func main() {

	// os.Open() opens specific file in
	// read-only mode and this return
	// a pointer of type os.File
	file, err := os.Open("testing-local.csv")

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
	// 1. Table with ACCEPT default policy
	// 2. Table with DROP default policy
	// 3. Add rule to ACCEPT when sourceIP == 10.0.0.252 (local)
	// 4. Delete rule
	// 5. Add rule to ACCEPT when protocol == "TCP" and sourceIP == 10.0.0.252
	// 6. Create a user chain
	// 7. Add rule to user chain to drop if sourcePort == 443
	// 8. Add jump to user chain after INPUT

	mainFilter := iptable.NewIPTable("DROP")

	mainFilter.AddRule("OUTPUT", "localRule", "10.0.0.252", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ACCEPT")
	mainFilter.DeleteRule("OUTPUT", "localRule")
	mainFilter.AddRule("INPUT", "protocolRule", "ANYVAL", "10.0.0.252", "ANYVAL", "ANYVAL", "TCP", "ANYVAL", "ACCEPT")
	mainFilter.AddUserChain("myChain")
	mainFilter.AddRule("myChain", "destPortRule", "ANYVAL", "ANYVAL", "ANYVAL", "62130", "UDP", "ANYVAL", "ACCEPT")
	mainFilter.AddRule("INPUT", "jumpRule", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "ANYVAL", "myChain")

	counter := filterData(mainFilter, records)
	fmt.Println("------------------------------------------------------------------------")
	fmt.Println("Above are all records that got through the firewall!")
	fmt.Println("Number of records: ", counter)
}
