package scanner_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/pivotal-cf/scantron/remotemachine"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Direct Scanning", func() {
	var (
		mockCtrl         *gomock.Controller
		directScan scanner.Scanner
		machine    *remotemachine.MockRemoteMachine

		systemInfo scantron.SystemInfo

		scanResults scanner.ScanResult
		scanErr     error
		logger scanlog.Logger
		buffer *bytes.Buffer

		fileMatch *scantron.FileMatch
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(Test)
		logger = scanlog.NewNopLogger()
		machine = remotemachine.NewMockRemoteMachine(mockCtrl)

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

		fileMatch = &scantron.FileMatch{
			MaxRegexFileSize: int64(1000),
		}

		buffer = &bytes.Buffer{}
		err := json.NewEncoder(buffer).Encode(systemInfo)
		Expect(err).NotTo(HaveOccurred())

		machine.EXPECT().Address().Return("10.0.0.1:22").AnyTimes()
		machine.EXPECT().Host().Return("10.0.0.1").AnyTimes()
		machine.EXPECT().OSName().Return("trusty").AnyTimes()
		machine.EXPECT().Password().Return("password").AnyTimes()

		directScan = scanner.Direct(machine)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Context("when no regex specified", func() {
		It("uploads and cleans the proc_scan binary to the remote machine", func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(buffer, nil).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
			scanResults, scanErr = directScan.Scan(fileMatch, logger)
		})
	})

	Context("when regexes specified", func() {
		BeforeEach(func() {
			fileMatch.PathRegexes = []string{"interesting"}
			fileMatch.ContentRegexes = []string{"valuable"}
		})

		It("uploads and cleans the proc_scan binary to the remote machine", func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000 --path 'interesting' --content 'valuable'").Return(buffer, nil).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
			scanResults, scanErr = directScan.Scan(fileMatch, logger)
		})
	})

	It("returns a report from the machine", func() {
		machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
		machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(buffer, nil).Times(1)
		machine.EXPECT().DeleteFile("./proc_scan").Times(1)
		scanResults, scanErr = directScan.Scan(fileMatch, logger)
		Expect(scanResults.JobResults).To(Equal([]scanner.JobResult{
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
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(errors.New("disaster")).Times(1)
		})

		It("fails to scan", func() {
			scanResults, scanErr = directScan.Scan(fileMatch, logger)
			Expect(scanErr).To(MatchError("disaster"))
		})
	})

	Context("when running the scanning binary fails", func() {
		BeforeEach(func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(nil, errors.New("disaster")).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
		})

		It("fails to scan", func() {
			scanResults, scanErr = directScan.Scan(fileMatch, logger)
			Expect(scanErr).To(MatchError("disaster"))
		})
	})
})
