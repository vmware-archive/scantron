package scanner

import (
	"fmt"
	"net"

	"code.cloudfoundry.org/lager"

	"github.com/pivotal-cf/scantron/remotemachine"
)

type direct struct {
	machine remotemachine.RemoteMachine
}

func Direct(machine remotemachine.RemoteMachine) Scanner {
	return &direct{
		machine: machine,
	}
}

func (d *direct) Scan(logger lager.Logger) ([]ScanResult, error) {
	l := logger.Session("scan")

	endpoint := fmt.Sprintf("%s", d.machine.Address())
	endpointLogger := l.Session("dial", lager.Data{
		"endpoint": endpoint,
	})

	systemInfo, err := scanMachine(endpointLogger, d.machine)
	if err != nil {
		endpointLogger.Error("failed-to-scan-machine", err)
		return nil, err
	}
	defer d.machine.Close()

	hostname, _, err := net.SplitHostPort(d.machine.Address())
	if err != nil {
		endpointLogger.Error("failed-to-unmarshal-output", err)
		return nil, err
	}

	scannedHost := buildScanResult(systemInfo, hostname, hostname)

	return []ScanResult{scannedHost}, nil
}
