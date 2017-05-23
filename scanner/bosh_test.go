package scanner_test

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/cppforlife/go-semi-semantic/version"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	boshdirector "github.com/cloudfoundry/bosh-cli/director"
	"github.com/cloudfoundry/bosh-cli/director/directorfakes"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/bosh/boshfakes"
	"github.com/pivotal-cf/scantron/remotemachine/remotemachinefakes"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Bosh Scanning", func() {
	var (
		boshScan scanner.Scanner
		director *boshfakes.FakeBoshDirector
		machine  *remotemachinefakes.FakeRemoteMachine

		vmInfo     []boshdirector.VMInfo
		systemInfo scantron.SystemInfo

		release1, release2 *directorfakes.FakeRelease
		releaseInfo        []boshdirector.Release

		scanResult scanner.ScanResult
		scanErr    error
	)

	BeforeEach(func() {
		machine = &remotemachinefakes.FakeRemoteMachine{}

		systemInfo = scantron.SystemInfo{
			Processes: []scantron.Process{
				{
					CommandName: "java",
					PID:         183,
					User:        "user-name",
				},
			},
			Files: []scantron.File{
				{Path: "a/path/to/the/file.txt"},
			},
		}

		buffer := &bytes.Buffer{}
		err := json.NewEncoder(buffer).Encode(systemInfo)
		Expect(err).NotTo(HaveOccurred())

		machine.AddressReturns("10.0.0.1")
		machine.RunCommandReturns(buffer, nil)

		director = &boshfakes.FakeBoshDirector{}
		director.ConnectToReturns(machine)

		vmInfo = []boshdirector.VMInfo{
			{
				JobName: "service",
				ID:      "id",
				IPs:     []string{"10.0.0.1"},
			},
		}

		release1 = &directorfakes.FakeRelease{}
		release1.NameReturns("release-1")
		version1, err := version.NewVersionFromString("1.1.1")
		Expect(err).NotTo(HaveOccurred())
		release1.VersionReturns(version1)

		release2 = &directorfakes.FakeRelease{}
		release2.NameReturns("release-2")
		version2, err := version.NewVersionFromString("2.2.2")
		Expect(err).NotTo(HaveOccurred())
		release2.VersionReturns(version2)

		releaseInfo = []boshdirector.Release{release1, release2}

		boshScan = scanner.Bosh(director)
	})

	JustBeforeEach(func() {
		director.VMsReturns(vmInfo)

		director.ReleasesReturns(releaseInfo)

		logger := scanlog.NewNopLogger()
		scanResult, scanErr = boshScan.Scan(logger)
	})

	It("cleans up the proc_scan binary after the scanning is done", func() {
		Expect(machine.DeleteFileCallCount()).To(Equal(1))

		remotePath := machine.DeleteFileArgsForCall(0)
		Expect(remotePath).To(Equal("./proc_scan"))
	})

	It("returns a report from the deployment", func() {
		Expect(scanResult).To(Equal(scanner.ScanResult{
			ReleaseResults: []scanner.ReleaseResult{
				{
					Name:    "release-1",
					Version: "1.1.1",
				},
				{
					Name:    "release-2",
					Version: "2.2.2",
				},
			},
			JobResults: []scanner.JobResult{
				{
					IP:       "10.0.0.1",
					Job:      "service/id",
					Services: systemInfo.Processes,
					Files:    systemInfo.Files,
				},
			},
		}))
	})

	Context("when the vm index is nil", func() {
		BeforeEach(func() {
			vmInfo[0].Index = nil
		})

		It("all still works", func() {
			Expect(scanErr).ShouldNot(HaveOccurred())
		})
	})

	Context("when uploading the scanning binary fails", func() {
		BeforeEach(func() {
			machine.UploadFileReturns(errors.New("disaster"))
		})

		It("keeps going", func() {
			Expect(scanErr).NotTo(HaveOccurred())
		})
	})

	Context("when running the scanning binary fails", func() {
		BeforeEach(func() {
			machine.RunCommandReturns(nil, errors.New("disaster"))
		})

		It("keeps going", func() {
			Expect(scanErr).NotTo(HaveOccurred())
		})
	})
})
