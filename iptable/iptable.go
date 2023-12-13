package iptable

// Table structure contains a set of chains
type Table struct {
	name   string
	chains []Chain
}

// chain structure
type Chain struct {
	name  string
	rules []Rule
}

// rules structure
type Rule struct {
	// target
	target string
	// matches
	SrcIP      string
	DstIP      string
	IPProtocol string
	DstPort    string
	SrcPort    string
	// ethernet   string
}

// function initialize IPtable
func NewIPTable() *Table {
	IPtable := new(Table)
	IPtable.name = "filter"
	return IPtable.defaultTable()
}

func (table *Table) defaultTable() *Table {

	rule := Rule{
		target: "ACCEPT",
	}

	rules := []Rule{rule}

	table.addChain("INPUT", rules)
	table.addChain("OUTPUT", rules)
	table.addChain("FORWARD", rules)
	return table
}

// function to add a chain
func (table *Table) addChain(name string, rules []Rule) *Table {

	chain := Chain{
		name:  name,
		rules: rules,
	}

	table.chains = append(table.chains, chain)
	return table
}
