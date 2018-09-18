package scanner

import (
	"github.com/pivotal-cf/scantron"
	"net"

	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanlog"
)

type direct struct {
	machine remotemachine.RemoteMachine
}

func Direct(machine remotemachine.RemoteMachine) Scanner {
	return &direct{
		machine: machine,
	}
}

func (d *direct) Scan(match *scantron.FileMatch, logger scanlog.Logger) (ScanResult, error) {
	hostLogger := logger.With(
		"host", d.machine.Address(),
	)

	systemInfo, err := scanMachine(match, hostLogger, d.machine)
	if err != nil {
		hostLogger.Errorf("Failed to scan machine: %s", err)
		return ScanResult{}, err
	}

	hostname, _, err := net.SplitHostPort(d.machine.Address())
	if err != nil {
		hostLogger.Errorf("Machine address was malformed: %s", err)
		return ScanResult{}, err
	}

	scannedHost := buildJobResult(systemInfo, hostname, hostname)

	return ScanResult{JobResults: []JobResult{scannedHost}}, nil
}
