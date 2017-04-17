package scanner

import (
	"fmt"
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

func (d *direct) Scan(logger scanlog.Logger) ([]ScanResult, error) {
	endpoint := fmt.Sprintf("%s", d.machine.Address())
	endpointLogger := logger.With(
		"endpoint", endpoint,
	)

	systemInfo, err := scanMachine(endpointLogger, d.machine)
	if err != nil {
		endpointLogger.Errorf("failed-to-scan-machine", err)
		return nil, err
	}
	defer d.machine.Close()

	hostname, _, err := net.SplitHostPort(d.machine.Address())
	if err != nil {
		endpointLogger.Errorf("failed-to-unmarshal-output", err)
		return nil, err
	}

	scannedHost := buildScanResult(systemInfo, hostname, hostname)

	return []ScanResult{scannedHost}, nil
}
