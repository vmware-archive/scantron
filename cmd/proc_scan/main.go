package main

import (
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
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
	var opts struct {
		Debug bool `long:"debug" description:"Show debug logs in output"`
		Context string `long:"context" description:"Log context"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	logger, err := scanlog.NewLogger(opts.Debug)
	if err != nil {
		log.Fatalln("failed to set up logger:", err)
	}
	logger = logger.With(
		"context", opts.Context,
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

	fs := filesystem.FileScanner{
		Walker: filesystem.NewWalker(filesystem.GetFileConfig(), logger),
		Metadata: filesystem.GetFileMetadata(),
		Logger:   logger,
	}
	files, err := fs.ScanFiles()
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
