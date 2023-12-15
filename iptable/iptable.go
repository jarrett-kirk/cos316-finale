package iptable

// TO DOS:
// 1. Testing
// 3. add possible target options
// 3. Jump!!
// 4. Routing !!
// 5. Write PAPER
// 6. DEMO VIDEO
// IF TIME
// 5. Editing rules
// 6. Inserting rules
// 7. Replacing rules
// 8. ERROR CHECKS!

import (
	"fmt"
	"net"
	"strings"
)

// packet stucture containing
type Packet struct {
	SourceIP   string
	DestIP     string
	SourcePort string
	DestPort   string
	Protocol   string
	Length     string
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
	name   string
	target string

	SrcIP    string
	DstIP    string
	Protocol string
	DstPort  string
	SrcPort  string
	Length   string
}

// function initialize IPtable
func NewIPTable(policy string) *Table {
	IPtable := new(Table)
	IPtable.chains = make(map[string]*Chain)
	IPtable.name = "filter"
	return IPtable.defaultTable(policy)
}

func (table *Table) defaultTable(policy string) *Table {
	table.AddChain("INPUT", policy)
	table.AddChain("OUTPUT", policy)
	table.AddChain("FORWARD", policy)
	return table
}

func (table *Table) ChangePolicy(chain string, policy string) {
	table.chains[chain].defaultPolicy = policy
}

// function to add a chain
func (table *Table) AddChain(name string, defaultPolicy string) {
	rule := []Rule{}

	chain := Chain{
		name:          name,
		rules:         rule,
		defaultPolicy: defaultPolicy,
	}

	table.chains[name] = &chain
}

// remove rule function (to avoid shifting the list just creates a new list)
func (table *Table) DeleteRule(chainName string, ruleName string) {
	chain := table.chains[chainName]
	rules := []Rule{}
	if chain != nil {
		for i := 0; i < len(chain.rules); i++ {
			if ruleName != chain.rules[i].name {
				rules = append(rules, chain.rules[i])
			}
		}
	}
	chain.rules = rules
}

// function to add a rule to a chain
func (table *Table) AddRule(chainName string, ruleName string, SrcIP string, DstIP string, Protocol string,
	DstPort string, SrcPort string, Length string, target string) {

	// get chain in the table
	chain := table.chains[chainName]

	rule := Rule{
		name:   ruleName,
		target: target,

		SrcIP:    SrcIP,
		DstIP:    DstIP,
		Protocol: Protocol,
		DstPort:  DstPort,
		SrcPort:  SrcPort,
		Length:   Length,
	}

	// if chain exists append rule to end of function
	if chain != nil {
		chain.rules = append(chain.rules, rule)
	}

}

// Takes in a Rule, which is a struct with all pertinent information to match. It also takes in
// The IP packet to check the conditions against
func checkRule(rule Rule, packet Packet) (target string) {
	if rule.DstIP == "ANYVAL" {
		rule.DstIP = packet.DestIP
	}
	if rule.SrcIP == "ANYVAL" {
		rule.SrcIP = packet.SourceIP
	}
	if rule.DstPort == "ANYVAL" {
		rule.DstPort = packet.DestPort
	}
	if rule.SrcPort == "ANYVAL" {
		rule.SrcPort = packet.SourcePort
	}
	if rule.Length == "ANYVAL" {
		rule.Length = packet.Length
	}
	if rule.Protocol == "ANYVAL" {
		rule.Protocol = packet.Protocol
	}

	if rule.DstIP == packet.DestIP && rule.SrcIP == packet.SourceIP && rule.SrcPort == packet.SourcePort && rule.DstPort == packet.DestPort && rule.Length == packet.Length && rule.Protocol == packet.Protocol {
		target = rule.target
	} else {
		target = ""
	}

	return target
}

func (table *Table) traverseSingleChain(packet Packet, chain Chain) (target string) {
	// iterate over all the rules in this chain
	for i := 0; i < len(chain.rules); i++ {
		target = checkRule(chain.rules[i], packet)
		fmt.Println("just checked the target: ", target)
		// if target is ACCEPT or DROP, break out immediately
		if target == "ACCEPT" || target == "DROP" {
			return target
		} else if target != "" {
			// if the target is the name of a chain, traverse that chain.
			for _, value := range table.chains {
				if target == value.name {
					table.traverseSingleChain(packet, *table.chains[value.name])
				}
			}
		}
	}
	target = ""
	return target
}

func (table *Table) TraverseChains(packet []string) (target string) {
	// First, routing decision. If it is destined for an outside network, only (filter FORWARD)
	//  if it stays local, (filter INPUT) and then (filter OUTPUT)
	packetData := Packet{
		SourceIP: packet[2],
		DestIP:   packet[3],
		Protocol: packet[4],
		Length:   packet[5],
	}
	if packetData.Protocol == "TCP" || packetData.Protocol == "UDP" {
		ports := strings.Fields(packet[6])
		packetData.SourcePort = ports[0]
		packetData.DestPort = ports[2]
	}
	fmt.Println("Packet Data ", packetData)

	local := true
	// get local addresses
	/*
		addrs, err := net.InterfaceAddrs()
		if err == nil {
			for i := 0; i < len(addrs); i++ {
				fmt.Println(addrs[i])
			}

		}
	*/

	ifaces, err := net.Interfaces()
	if err == nil {
		// handle err
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				break
			}
			// handle err
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				// process IP address
				fmt.Println("ip: ", ip)
			}
		}
	}

	// check if local is not true and set to false if necessary
	// net.Interfaces()

	// If ACCEPT or DROP are ever come across, just return target
	// While traversing a chain, if the target is a JUMP, go into the new chain
	// If nothing catches the packet in this new jumped chain, go back to the original chain

	if local {
		// iterate over all the rules in INPUT first
		target := table.traverseSingleChain(packetData, *table.chains["INPUT"])
		fmt.Println("target after traverseSingleChain: ", target)
		if target == "ACCEPT" || target == "DROP" {
			return target
		} else if target == "" {
			fmt.Println("using the defualt policy for INPUT")
			target = table.chains["INPUT"].defaultPolicy
			return target
		}
	} else {
		target := table.traverseSingleChain(packetData, *table.chains["FORWARD"])
		if target == "" {
			fmt.Println("using the defualt policy for FORWARD")
			target = table.chains["FORWARD"].defaultPolicy
			return target
		}
	}

	fmt.Println("target before return: ", target)
	return target

}
