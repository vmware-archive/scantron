package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"code.cloudfoundry.org/lager"

	"github.com/pivotal-cf/scantron"
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

	filepath := "./proc_scan"

	if err := d.machine.UploadFile(filepath, filepath); err != nil {
		endpointLogger.Error("failed-to-upload-file", err)
		return nil, err
	}

	defer d.machine.DeleteFile(filepath)

	output, err := d.machine.RunCommand(filepath)
	if err != nil {
		endpointLogger.Error("failed-to-run-command", err, lager.Data{
			"command": filepath,
		})
		return nil, err
	}

	scannedHost, err := d.decodeScannedHost(output)
	if err != nil {
		endpointLogger.Error("failed-to-unmarshal-output", err)
		return nil, err
	}

	scannedHosts := []ScanResult{scannedHost}

	return scannedHosts, nil
}

func (d *direct) decodeScannedHost(reader io.Reader) (ScanResult, error) {
	var host scantron.SystemInfo

	err := json.NewDecoder(reader).Decode(&host)
	if err != nil {
		return ScanResult{}, err
	}

	return buildScanResult(host, d.machine.Address(), d.machine.Address()), nil
}
