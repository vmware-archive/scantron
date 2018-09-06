package main

import (
	"encoding/json"
	"fmt"
	"github.com/pivotal-cf/scantron/filesystem"
	"github.com/pivotal-cf/scantron/ssh"
	"github.com/pivotal-cf/scantron/tlsscan"
	"os"

	"log"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/process"
	"github.com/pivotal-cf/scantron/scanlog"
)

func main() {

	address := os.Args[1]
	logger, err := scanlog.NewLogger(false)
	if err != nil {
		log.Fatalln("failed to set up logger:", err)
	}
	logger = logger.With(
		"host", address,
	)

	processScanner := process.ProcessScanner{
		SysRes: &process.SystemResourceImpl {},
		TlsScan: &tlsscan.TlsScannerImpl {},
	}

	processes, err := processScanner.ScanProcesses(logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get process list:", err)
		os.Exit(1)
	}

	files, err := filesystem.ScanFiles()
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
