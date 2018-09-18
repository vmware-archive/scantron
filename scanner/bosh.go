package scanner

import (
	"fmt"
	"github.com/pivotal-cf/scantron"
	"strconv"
	"sync"

	"github.com/pivotal-cf/scantron/bosh"
	"github.com/pivotal-cf/scantron/scanlog"
)

type boshScanner struct {
  deployment bosh.TargetDeployment
}

func Bosh(deployment bosh.TargetDeployment) Scanner {
  return &boshScanner{
    deployment: deployment,
  }
}

func (s *boshScanner) Scan(fileRegexes *scantron.FileMatch, logger scanlog.Logger) (ScanResult, error) {
	vms := s.deployment.VMs()

	wg := &sync.WaitGroup{}
	wg.Add(len(vms))

	hosts := make(chan JobResult)

	err := s.deployment.Setup()
	if err != nil {
		return ScanResult{}, err
	}
	defer s.deployment.Cleanup()

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

			remoteMachine := s.deployment.ConnectTo(vm)
			defer remoteMachine.Close()

			systemInfo, err := scanMachine(fileRegexes, machineLogger, remoteMachine)
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

	releaseResults := []ReleaseResult{}
	for _, release := range s.deployment.Releases() {
		releaseResults = append(releaseResults, ReleaseResult{Name: release.Name(), Version: release.Version().String()})
	}

	return ScanResult{
		JobResults:     scannedHosts,
		ReleaseResults: releaseResults,
	}, nil
}

func index(index *int) string {
	if index == nil {
		return "?"
	}

	return strconv.Itoa(*index)
}
