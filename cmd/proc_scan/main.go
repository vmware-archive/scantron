package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/filesystem"
	"github.com/pivotal-cf/scantron/process"
	"github.com/pivotal-cf/scantron/ssh"
)

func main() {
	processes, err := process.ScanProcesses()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get process list:", err)
		os.Exit(1)
	}

	excludedPaths := []string{
		"/dev", "/proc", "/sys", "/run",
	}

	files, err := filesystem.ScanFilesystem("/", excludedPaths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to scan filesystem:", err)
		os.Exit(1)
	}

	sshKeys, err := ssh.ScanSSH("localhost:22")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to scan ssh keys:", err)
		os.Exit(1)
	}

	systemInfo := scantron.SystemInfo{
		Processes: processes,
		Files:     files,
		SSHKeys:   sshKeys,
	}

	json.NewEncoder(os.Stdout).Encode(systemInfo)
}
