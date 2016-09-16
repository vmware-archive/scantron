package scanner

import (
	"code.cloudfoundry.org/lager"

	"github.com/pivotal-cf/scantron"
)

type Scanner interface {
	Scan(lager.Logger) ([]ScanResult, error)
}

type ScanResult struct {
	IP  string
	Job string

	Services []scantron.Process
	Files    []scantron.File
}

func buildScanResult(host scantron.SystemInfo, jobName, address string) ScanResult {
	return ScanResult{
		Job:      jobName,
		IP:       address,
		Services: host.Processes,
		Files:    host.Files,
	}
}
