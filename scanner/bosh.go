package scanner

import (
	"encoding/json"
	"fmt"
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

			err := remoteMachine.DeleteFile("/tmp/proc_scan")
			if err != nil {
				machineLogger.Error("failed-to-run-cmd", err)
				return
			}

			err = remoteMachine.UploadFile("./proc_scan", "/tmp")
			if err != nil {
				machineLogger.Error("failed-to-scp-proc-scan", err)
				return
			}

			_, err = remoteMachine.RunCommand("mv /tmp/proc_scan /var/vcap/")
			if err != nil {
				machineLogger.Error("failed-to-move-proc-scan", err)
				return
			}
			defer remoteMachine.DeleteFile("/var/vcap/proc_scan")

			output, err := remoteMachine.RunCommand("/var/vcap/proc_scan")
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
