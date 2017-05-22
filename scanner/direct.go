package scanner

import (
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

func (d *direct) Scan(logger scanlog.Logger) (ScanResult, error) {
	hostLogger := logger.With(
		"host", d.machine.Address(),
	)

	systemInfo, err := scanMachine(hostLogger, d.machine)
	if err != nil {
		hostLogger.Errorf("Failed to scan machine: %s", err)
		return ScanResult{}, err
	}
	defer d.machine.Close()

	hostname, _, err := net.SplitHostPort(d.machine.Address())
	if err != nil {
		hostLogger.Errorf("Machine address was malformed: %s", err)
		return ScanResult{}, err
	}

	scannedHost := buildJobResult(systemInfo, hostname, hostname)

	return ScanResult{JobResults: []JobResult{scannedHost}}, nil
}
