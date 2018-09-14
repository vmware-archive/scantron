package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/rakyll/statik/fs"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanlog"
	_ "github.com/pivotal-cf/scantron/statik"
)

type Scanner interface {
	Scan(scanlog.Logger) (ScanResult, error)
}

type ScanResult struct {
	JobResults     []JobResult
	ReleaseResults []ReleaseResult
}

type JobResult struct {
	IP  string
	Job string

	Services []scantron.Process
	Files    []scantron.File
	SSHKeys  []scantron.SSHKey
}

type ReleaseResult struct {
	Name    string
	Version string
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

func writeProcScanToTempFile(osName string) (string, error) {
	data_path := "/proc_scan/proc_scan_linux"
	if strings.Contains(osName, "windows") {
		data_path = "/proc_scan/proc_scan_windows"
	}
	statikFS, err := fs.New()
	if err != nil {
		return "", err
	}

	data, err := fs.ReadFile(statikFS, data_path)
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

	osName := remoteMachine.OSName()
	logger.Debugf("Deployment stemcell is %s", osName)

	srcFilePath, err := writeProcScanToTempFile(osName)
	if err != nil {
		return systemInfo, err
	}
	defer os.Remove(srcFilePath)

	dstFilePath := "./proc_scan"
	command := fmt.Sprintf("echo %s | sudo -S -- %s", remoteMachine.Password(), dstFilePath)
	if strings.Contains(osName, "windows") {
		dstFilePath = ".\\proc_scan.exe"
		command = ".\\proc_scan.exe"
	}

	if scantron.Debug {
		command = strings.Join([]string{command, "--debug"}, " ")
	}
	command = strings.Join([]string{command, "--context", remoteMachine.Host()}, " ")

	err = remoteMachine.UploadFile(srcFilePath, dstFilePath)
	if err != nil {
		logger.Errorf("Failed to upload scanner to remote machine: %s", err)
		return systemInfo, err
	}

	defer remoteMachine.DeleteFile(dstFilePath)
	output, err := remoteMachine.RunCommand(command)
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
