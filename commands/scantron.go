package commands

type ScantronCommand struct {
	BoshScan   BoshScanCommand   `command:"bosh-scan" description:"Scan all of the machines in a BOSH deployment"`
	DirectScan DirectScanCommand `command:"direct-scan" description:"Scan a single machine"`
	Audit      AuditCommand      `command:"audit" description:"audit a scan report for unexpected hosts, processes, and ports "`
}

var Scantron ScantronCommand
