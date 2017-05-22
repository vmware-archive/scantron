package scanner

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanlog"
)

type Scanner interface {
	Scan(scanlog.Logger) (ScanResult, error)
}

type ScanResult struct {
	JobResults []JobResult
}

type JobResult struct {
	IP  string
	Job string

	Services []scantron.Process
	Files    []scantron.File
	SSHKeys  []scantron.SSHKey
}

func buildJobResult(host scantron.SystemInfo, jobName, address string) JobResult {
	return JobResult{
		Job:      jobName,
		IP:       address,
		Services: host.Processes,
		Files:    host.Files,
		SSHKeys:  host.SSHKeys,
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

func scanMachine(logger scanlog.Logger, remoteMachine remotemachine.RemoteMachine) (scantron.SystemInfo, error) {
	var systemInfo scantron.SystemInfo

	logger.Infof("Starting VM scan")
	defer logger.Infof("VM scan complete")

	srcFilePath, err := writeProcScanToTempFile()
	if err != nil {
		return systemInfo, err
	}
	defer os.Remove(srcFilePath)

	dstFilePath := "./proc_scan"

	err = remoteMachine.UploadFile(srcFilePath, dstFilePath)
	if err != nil {
		logger.Errorf("Failed to upload scanner to remote machine: %s", err)
		return systemInfo, err
	}

	defer remoteMachine.DeleteFile(dstFilePath)

	output, err := remoteMachine.RunCommand(dstFilePath)
	if err != nil {
		logger.Errorf("Failed to run scanner on remote machine: %s", err)
		return systemInfo, err
	}

	err = json.NewDecoder(output).Decode(&systemInfo)
	if err != nil {
		logger.Errorf("Scanner results were malformed: %s", err)
		return systemInfo, err
	}

	return systemInfo, nil
}
