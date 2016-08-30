package commands

type ScantronCommand struct {
	BoshScan   BoshScanCommand   `command:"bosh-scan" description:"Scan all of the machines in a BOSH deployment"`
	DirectScan DirectScanCommand `command:"direct-scan" description:"Scan a single machine"`
}

var Scantron ScantronCommand
