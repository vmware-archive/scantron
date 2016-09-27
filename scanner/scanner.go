package scanner

import (
	"bytes"
	"io"
	"os"

	"code.cloudfoundry.org/lager"

	"github.com/pivotal-cf/scantron"
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

func convertBinaryToFile(binary []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := bytes.NewBuffer(binary)

	_, err = io.Copy(file, buffer)
	if err != nil {
		return err
	}

	return nil
}
