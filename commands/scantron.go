package commands

type ScantronCommand struct {
	BoshScan         BoshScanCommand         `command:"bosh-scan" description:"Scan all of the machines in a BOSH deployment"`
	DirectScan       DirectScanCommand       `command:"direct-scan" description:"Scan a single machine"`
	Audit            AuditCommand            `command:"audit" description:"Audit a scan report for unexpected hosts, processes, and ports "`
	GenerateManifest GenerateManifestCommand `command:"generate-manifest" description:"Generate a audit manifest from the last report"`
}

var Scantron ScantronCommand
