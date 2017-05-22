package scanner

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/pivotal-cf/scantron/bosh"
	"github.com/pivotal-cf/scantron/scanlog"
)

type boshScanner struct {
	director bosh.BoshDirector
}

func Bosh(director bosh.BoshDirector) Scanner {
	return &boshScanner{
		director: director,
	}
}

func (s *boshScanner) Scan(logger scanlog.Logger) (ScanResult, error) {
	vms := s.director.VMs()

	wg := &sync.WaitGroup{}
	wg.Add(len(vms))

	hosts := make(chan JobResult)

	err := s.director.Setup()
	if err != nil {
		return ScanResult{}, err
	}
	defer s.director.Cleanup()

	for _, vm := range vms {
		vm := vm

		go func() {
			defer wg.Done()

			ip := bosh.BestAddress(vm.IPs)

			machineLogger := logger.With(
				"job", vm.JobName,
				"id", vm.ID,
				"index", index(vm.Index),
				"address", ip,
			)

			remoteMachine := s.director.ConnectTo(machineLogger, vm)
			defer remoteMachine.Close()

			systemInfo, err := scanMachine(machineLogger, remoteMachine)
			if err != nil {
				machineLogger.Errorf("Failed to scan machine: %s", err)
				return
			}

			boshName := fmt.Sprintf("%s/%s", vm.JobName, vm.ID)
			hosts <- buildJobResult(systemInfo, boshName, ip)
		}()
	}

	go func() {
		wg.Wait()
		close(hosts)
	}()

	var scannedHosts []JobResult

	for host := range hosts {
		scannedHosts = append(scannedHosts, host)
	}

	return ScanResult{JobResults: scannedHosts}, nil
}

func index(index *int) string {
	if index == nil {
		return "?"
	}

	return strconv.Itoa(*index)
}
