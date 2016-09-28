package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"sync"

	"code.cloudfoundry.org/lager"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
)

type boshScanner struct {
	director remotemachine.BoshDirector
}

func Bosh(director remotemachine.BoshDirector) Scanner {
	return &boshScanner{
		director: director,
	}
}

func (s *boshScanner) Scan(logger lager.Logger) ([]ScanResult, error) {
	vms := s.director.VMs()

	wg := &sync.WaitGroup{}
	wg.Add(len(vms))

	hosts := make(chan ScanResult)

	binary, err := scantron.Asset("data/proc_scan")
	if err != nil {
		logger.Error("failed-to-find-proc-scan", err)
		return []ScanResult{}, errors.New("failed-to-find-proc-scan-binary")
	}

	tmpFile, err := ioutil.TempFile("", "proc_scan")
	if err != nil {
		logger.Error("failed-to-create-file", err)
		return nil, err
	}
	srcFilePath := tmpFile.Name()
	defer os.Remove(srcFilePath)

	if err := convertBinaryToFile(binary, srcFilePath); err != nil {
		logger.Error("failed-to-convert-proc-scan-binary-to-file", err)
		return []ScanResult{}, errors.New("failed-to-convert-proc-scan")
	}

	os.Chmod(srcFilePath, 0700)
	defer os.Remove(srcFilePath)

	for _, vm := range vms {
		vm := vm

		go func() {
			defer wg.Done()
			machineLogger := logger.Session("scanning-machine", lager.Data{
				"job":     vm.JobName,
				"id":      vm.ID,
				"index":   index(vm.Index),
				"address": fmt.Sprintf("%s", vm.IPs[0]),
			})

			remoteMachine := s.director.ConnectTo(machineLogger, vm)
			defer remoteMachine.Close()

			err = remoteMachine.UploadFile(srcFilePath, "~/proc_scan")
			if err != nil {
				machineLogger.Error("failed-to-scp-proc-scan", err)
				return
			}

			defer remoteMachine.DeleteFile("~/proc_scan")

			output, err := remoteMachine.RunCommand("~/proc_scan")
			if err != nil {
				machineLogger.Error("failed-to-run-proc-scan", err)
				return
			}

			var systemInfo scantron.SystemInfo

			err = json.NewDecoder(output).Decode(&systemInfo)
			if err != nil {
				machineLogger.Error("failed-to-decode-result", err)
				return
			}

			boshName := fmt.Sprintf("%s/%s", vm.JobName, vm.ID)
			hosts <- buildScanResult(systemInfo, boshName, vm.IPs[0])
		}()
	}

	go func() {
		wg.Wait()
		close(hosts)
	}()

	var scannedHosts []ScanResult

	for host := range hosts {
		scannedHosts = append(scannedHosts, host)
	}

	return scannedHosts, nil
}

func index(index *int) string {
	if index == nil {
		return "?"
	}

	return strconv.Itoa(*index)
}
