package iptable

// rules structure
type Rule struct {
	// target
	target string
	// matches
}

// chain structure
type Chain struct {
	name  string
	rules []*Rule
}

// Table structure contains a set of chains

// function to add a chain
func addChain() {

}

// function to add a rule
func addRule() {

}
