package scanner_test

import (
	"bytes"
	"encoding/json"
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/lager/lagertest"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine/remotemachinefakes"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Direct Scanning", func() {
	var (
		directScan scanner.Scanner
		machine    *remotemachinefakes.FakeRemoteMachine

		systemInfo scantron.SystemInfo

		scanResults []scanner.ScanResult
		scanErr     error
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

		machine.AddressReturns("10.0.0.1:22")
		machine.RunCommandReturns(buffer, nil)

		directScan = scanner.Direct(machine)
	})

	JustBeforeEach(func() {
		logger := lagertest.NewTestLogger("direct")
		scanResults, scanErr = directScan.Scan(logger)
	})

	It("uploads the proc_scan binary to the remote machine", func() {
		Expect(machine.UploadFileCallCount()).To(Equal(1))

		localPath, remotePath := machine.UploadFileArgsForCall(0)
		Expect(localPath).To(ContainSubstring("/proc_scan"))
		Expect(remotePath).To(Equal("./proc_scan"))
	})

	It("cleans up the proc_scan binary after the scanning is done", func() {
		Expect(machine.DeleteFileCallCount()).To(Equal(1))

		remotePath := machine.DeleteFileArgsForCall(0)
		Expect(remotePath).To(Equal("./proc_scan"))
	})

	It("returns a report from the machine", func() {
		Expect(scanResults).To(Equal([]scanner.ScanResult{
			{
				IP:       "10.0.0.1",
				Job:      "10.0.0.1",
				Services: systemInfo.Processes,
				Files:    systemInfo.Files,
			},
		}))
	})

	Context("when uploading the scanning binary fails", func() {
		BeforeEach(func() {
			machine.UploadFileReturns(errors.New("disaster"))
		})

		It("fails to scan", func() {
			Expect(scanErr).To(MatchError("disaster"))
		})
	})

	Context("when running the scanning binary fails", func() {
		BeforeEach(func() {
			machine.RunCommandReturns(nil, errors.New("disaster"))
		})

		It("fails to scan", func() {
			Expect(scanErr).To(MatchError("disaster"))
		})
	})
})
