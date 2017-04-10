package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/filesystem"
	"github.com/pivotal-cf/scantron/process"
)

func main() {
	processes, err := process.ScanProcesses()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get process list:", err)
		os.Exit(1)
	}

	files, err := filesystem.ScanFilesystem("/", []string{
		"/dev", "/proc", "/sys",
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to scan filesystem:", err)
		os.Exit(1)
	}

	systemInfo := scantron.SystemInfo{
		Processes: processes,
		Files:     files,
	}

	json.NewEncoder(os.Stdout).Encode(systemInfo)
}
