package iptable

import (
	"fmt"
)

// packet stucture containing
type Packet struct {
	SourceIP string
	DestIP   string
}

// Table structure contains a set of chains
type Table struct {
	name   string
	chains map[string]*Chain
}

// chain structure
type Chain struct {
	name          string
	rules         []Rule
	defaultPolicy string
}

// rules structure
type Rule struct {
	// target
	target string
	// matches
	SrcIP string
	DstIP string
	// IPProtocol string
	DstPort string
	SrcPort string
	// ethernet   string
}

// function initialize IPtable
func NewIPTable(policy string) *Table {
	IPtable := new(Table)
	IPtable.chains = make(map[string]*Chain)
	IPtable.name = "filter"
	return IPtable.defaultTable(policy)
}

func (table *Table) defaultTable(policy string) *Table {
	table.addChain("INPUT", policy)
	table.addChain("OUTPUT", policy)
	table.addChain("FORWARD", policy)
	return table
}

func (table *Table) getTableInfo() (string, map[string]*Chain) {
	return table.name, table.chains
}

func (table *Table) changePolicy(chain string, policy string) {
	table.chains[chain].defaultPolicy = policy
}

// function to add a chain
func (table *Table) addChain(name string, defaultPolicy string) {
	rule := []Rule{}

	chain := Chain{
		name:          name,
		rules:         rule,
		defaultPolicy: defaultPolicy,
	}

	table.chains[name] = &chain
}

// function to add a rule to a chain
func (table *Table) addRule(chainName string, SrcIP string, DstIP string, DstPort string, SrcPort string, target string) {

	// get chain in the table
	chain := table.chains[chainName]

	rule := Rule{
		// target
		target: target,
		// matches
		SrcIP: SrcIP,
		DstIP: DstIP,
		// IPProtocol string
		DstPort: DstPort,
		SrcPort: SrcPort,
		// ethernet   string
	}

	// if chain exists append rule to end of function
	if chain != nil {
		chain.rules = append(chain.rules, rule)
	}
	return
}

// Takes in a Rule, which is a struct with all pertinent information to match. It also takes in
// The IP packet to check the conditions against
func checkRule(rule Rule, packet Packet) (target string) {

	// check if it matches
	if rule.DstIP == packet.DestIP && rule.SrcIP == packet.SourceIP {
		target = rule.target
	} else {
		target = ""
	}

	return target

	/*
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); tcpLayer != nil {
			fmt.Println("This is a IPv4 packet!")
			// Get actual IPv4 data from this layer
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			fmt.Printf("From src ip %d to dst ip %d\n", ipv4.SrcIP, ipv4.DstIP)
		}
	*/

	// target := rule.target
	// dstIP := rule.DstIP
	// dstPort := rule.DstPort
	// srcIP := rule.SrcIP
	// srcPort := rule.SrcPort
}

// remove rule function

func (table *Table) TraverseChains(packet []string) (target string) {
	// First, routing decision. If it is destined for an outside network, only (filter FORWARD)
	//  if it stays local, (filter INPUT) and then (filter OUTPUT)
	fmt.Println("Packet argument: ", packet)
	packetData := Packet{
		SourceIP: packet[2],
		DestIP:   packet[3],
	}
	fmt.Println("Packet Data ", packetData)

	local := true
	// check if local is not true and set to false if necessary
	// net.Interfaces()

	// If ACCEPT or DROP are ever come across, just return target
	// While traversing a chain, if the target is a JUMP, go into the new chain
	// If nothing catches the packet in this new jumped chain, go back to the original chain

	if local == true {
		// iterate over all the rules in INPUT first
		for i := 0; i < len(table.chains["INPUT"].rules); i++ {
			target = checkRule(table.chains["INPUT"].rules[i], packetData)
		}
		if target == "" {
			target = table.chains["INPUT"].defaultPolicy
		}
	} else {
		// TO DO: ELSE CASE HANDLES FOWARDING
	}

	// return
	return target

}
