package scanner

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
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
