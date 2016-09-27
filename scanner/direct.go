package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

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

	binary, err := scantron.Asset("data/proc_scan")
	if err != nil {
		endpointLogger.Error("failed-to-locate-proc-scan", err)
		return nil, err
	}

	tmpFile, err := ioutil.TempFile("", "proc_scan")
	if err != nil {
		endpointLogger.Error("failed-to-create-file", err)
		return nil, err
	}
	srcFilePath := tmpFile.Name()
	defer os.Remove(srcFilePath)

	if err := convertBinaryToFile(binary, srcFilePath); err != nil {
		endpointLogger.Error("failed-to-convert-proc-scan-binary", err)
		return nil, err
	}
	dstFilePath := "./proc_scan"
	defer d.machine.DeleteFile(dstFilePath)

	if err := d.machine.UploadFile(srcFilePath, dstFilePath); err != nil {
		endpointLogger.Error("failed-to-upload-file", err)
		return nil, err
	}

	output, err := d.machine.RunCommand(dstFilePath)
	if err != nil {
		endpointLogger.Error("failed-to-run-command", err, lager.Data{
			"command": dstFilePath,
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
