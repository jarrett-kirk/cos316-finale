package iptable

import (
	"net"
	"strings"
)

// packet stucture for handling incoming packet data
type Packet struct {
	SourceIP   string
	DestIP     string
	SourcePort string
	DestPort   string
	Protocol   string
	Length     string
}

// Table structure
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
	name     string
	target   string
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Length   string
}

/*
	Initializes a new IPTable/Firewall takes as input a string policy

which specifies the default policy for the chains
*/
func NewIPTable(policy string) *Table {
	IPtable := new(Table)
	IPtable.chains = make(map[string]*Chain)
	IPtable.name = "filter"
	return IPtable.defaultTable(policy)
}

/*
Helper function for setting up the IPTable by creating
default chains for the filter
*/
func (table *Table) defaultTable(policy string) *Table {
	table.addChain("INPUT", policy)
	table.addChain("OUTPUT", policy)
	table.addChain("FORWARD", policy)
	return table
}

// Helper function for adding default chains with specified policy
func (table *Table) addChain(name string, defaultPolicy string) {
	rule := []Rule{}
	chain := Chain{
		name:          name,
		rules:         rule,
		defaultPolicy: defaultPolicy,
	}
	table.chains[name] = &chain
}

/*
	Function for users to create user chains. Takes the name of the

chain as argument and adds chain table. Note: user chains do not have a
default policy
*/
func (table *Table) AddUserChain(name string) {
	rule := []Rule{}

	chain := Chain{
		name:  name,
		rules: rule,
	}

	table.chains[name] = &chain
}

/*
	function that allows users to change the default policy for

the chains in the table if they are one of the default chains.
Returns true if successful and false if chain was not a valid default chain
*/
func (table *Table) ChangePolicy(chain string, policy string) bool {
	if chain == "INPUT" || chain == "OUTPUT" || chain == "FORWARD" {
		table.chains[chain].defaultPolicy = policy
		return true
	}
	return false
}

/*
	function that takes as input two strings specifing a chain name

and rule name. If that chain exists updates that chains rules by creating a
new rule list that doesnt contain the specified rule if it exists and
return true. If there is not such chain return false
*/
func (table *Table) DeleteRule(chainName string, ruleName string) bool {
	chain := table.chains[chainName]
	rules := []Rule{}
	if chain != nil {
		for i := 0; i < len(chain.rules); i++ {
			if ruleName != chain.rules[i].name {
				rules = append(rules, chain.rules[i])
			}
		}
		chain.rules = rules
		return true
	}
	return false
}

/*
	Function that adds a rule to the specified chain. Takes the chain name and rule name

and each of the parameters possible for matching on a rulename (SrcIP, DstIP, SrcPort, DstPort,
Protocol, Length) as well as the rule target. Returns true if successful or false if unsuccessful
*/
func (table *Table) AddRule(chainName string, ruleName string, SrcIP string, DstIP string,
	SrcPort string, DstPort string, Protocol string, Length string, target string) bool {

	// get chain in the table
	chain := table.chains[chainName]
	// create rule
	rule := Rule{
		name:     ruleName,
		target:   target,
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
		return true
	}
	return false

}

/*
	Helper function: Takes in a Rule, which is a struct with all pertinent information to match. It also takes in

The IP packet to check the conditions against. Returns the target of that rule if all the conditions are matched
or an empty string if not
*/
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
	if rule.SrcIP == packet.SourceIP && rule.DstIP == packet.DestIP && rule.SrcPort == packet.SourcePort && rule.DstPort == packet.DestPort && rule.Protocol == packet.Protocol && rule.Length == packet.Length {
		target = rule.target
	} else {
		target = ""
	}
	return target
}

// helper function that traverses a single chain
func (table *Table) traverseSingleChain(packet Packet, chain Chain) (target string) {
	// iterate over all the rules in this chain
	for i := 0; i < len(chain.rules); i++ {
		target = checkRule(chain.rules[i], packet)
		// fmt.Println("just checked the target: ", target)
		// if t`arget is ACCEPT or DROP, break out immediately
		if target == "ACCEPT" || target == "DROP" {
			return target
		} else if target != "" {
			// if the target is the name of a chain, traverse that chain.
			for _, value := range table.chains {
				if target == value.name {
					target = table.traverseSingleChain(packet, *table.chains[value.name])
					if target == "ACCEPT" || target == "DROP" {
						return target
					}
				}
			}
		}
	}
	target = ""
	return target
}

/*
routing helper function takes as input packetData in the form of a Packet struct.
Gets the local network information and IP addresses then compares it to the data
in the packet. If the source addresses match return localSource as true if not return it as false
and same for localDest with the destination address
*/
func (table *Table) routingDecision(packetData Packet) (localSource bool, localDest bool) {
	localSource = false
	localDest = false
	// get local addresses
	localAddrs := []net.IP{}
	// Section adapted from : https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
	// Author: Sebastian Original source: https://go.dev/play/p/BDt3qEQ_2H
	// list of all system interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		// handle err
		for _, i := range ifaces {
			// get addresses
			addrs, err := i.Addrs()
			if err != nil {
				break
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				// process IP address
				localAddrs = append(localAddrs, ip)
			}
		}
	}

	// Check if source address is local address
	for i := 0; i < len(localAddrs); i++ {
		if packetData.SourceIP == localAddrs[i].To16().String() {
			localSource = true
		}
		if packetData.DestIP == localAddrs[i].To16().String() {
			localDest = true
		}
	}
	return localSource, localDest
}

/*
	Takes as input a packet routes the packet to the correct chain in the table

and then traverses the rules in that table until a target decision is made. Returns
the result of the filtering.
*/
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
		for i := 0; i < len(ports); i++ {
			if ports[i] == ">" {
				packetData.SourcePort = ports[i-1]
				packetData.DestPort = ports[i+1]
			}
		}
	}

	localSource, localDest := table.routingDecision(packetData)

	// used for testing packets
	// localDest = true
	// localSource = true

	// If ACCEPT or DROP are ever come across, just return target
	// While traversing a chain, if the target is a JUMP, go into the new chain
	// If nothing catches the packet in this new jumped chain, go back to the original chain
	if localDest || localSource {
		if localDest {
			// iterate over all the rules in INPUT
			target := table.traverseSingleChain(packetData, *table.chains["INPUT"])
			if target == "ACCEPT" || target == "DROP" {
				return target
			} else if target == "" {
				target = table.chains["INPUT"].defaultPolicy
				return target
			}
		}
		if localSource {
			// iterate over all the rules in OUTPUT
			target := table.traverseSingleChain(packetData, *table.chains["OUTPUT"])
			if target == "ACCEPT" || target == "DROP" {
				return target
			} else if target == "" {
				target = table.chains["OUTPUT"].defaultPolicy
				return target
			}
		}
	} else {
		target := table.traverseSingleChain(packetData, *table.chains["FORWARD"])
		if target == "" {
			target = table.chains["FORWARD"].defaultPolicy
			return target
		}
	}
	return target
}
