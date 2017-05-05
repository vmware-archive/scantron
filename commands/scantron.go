package commands

type ScantronCommand struct {
	Debug bool `long:"debug" description:"Show debug logs in output"`

	BoshScan         BoshScanCommand         `command:"bosh-scan" description:"Scan all of the machines in a BOSH deployment"`
	DirectScan       DirectScanCommand       `command:"direct-scan" description:"Scan a single machine"`
	Audit            AuditCommand            `command:"audit" description:"Audit a scan report for unexpected hosts, processes, and ports"`
	GenerateManifest GenerateManifestCommand `command:"generate-manifest" description:"Generate a audit manifest from the last report"`
}

var Scantron ScantronCommand

type ExitStatusError struct {
	message    string
	exitStatus int
}

func (e ExitStatusError) ExitStatus() int {
	return e.exitStatus
}

func (e ExitStatusError) Error() string {
	return e.message
}
