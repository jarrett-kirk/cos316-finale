package iptable

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
	ethernet   string
}

// chain structure
type Chain struct {
	name  string
	rules []*Rule
}

// Table structure contains a set of chains
type Table struct {
	name   string
	chains []*Chain
}

// function initialize IPtable
func NewIPTable() *Table {
	filter := new(Table)
	return filter
}

// function to add a chain
func addChain() {

}

// function to add a rule
func addRule() {

}
