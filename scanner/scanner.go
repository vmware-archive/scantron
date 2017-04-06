package scanner

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"code.cloudfoundry.org/lager"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
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

func writeProcScanToTempFile() (string, error) {
	data, err := scantron.Asset("data/proc_scan")
	if err != nil {
		return "", err
	}

	tmpFile, err := ioutil.TempFile("", "proc_scan")
	if err != nil {
		return "", err
	}

	err = ioutil.WriteFile(tmpFile.Name(), data, 0644)
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func scanMachine(logger lager.Logger, remoteMachine remotemachine.RemoteMachine) (scantron.SystemInfo, error) {
	var systemInfo scantron.SystemInfo

	srcFilePath, err := writeProcScanToTempFile()
	if err != nil {
		return systemInfo, err
	}
	defer os.Remove(srcFilePath)

	dstFilePath := "./proc_scan"

	err = remoteMachine.UploadFile(srcFilePath, dstFilePath)
	if err != nil {
		logger.Error("failed-to-scp-proc-scan", err)
		return systemInfo, err
	}

	defer remoteMachine.DeleteFile(dstFilePath)

	output, err := remoteMachine.RunCommand(dstFilePath)
	if err != nil {
		logger.Error("failed-to-run-proc-scan", err)
		return systemInfo, err
	}

	err = json.NewDecoder(output).Decode(&systemInfo)
	if err != nil {
		logger.Error("failed-to-decode-result", err)
		return systemInfo, err
	}

	return systemInfo, nil
}
