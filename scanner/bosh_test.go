package scanner_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/pivotal-cf/scantron/bosh"
	"github.com/pivotal-cf/scantron/remotemachine"

	"github.com/cppforlife/go-semi-semantic/version"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	boshdirector "github.com/cloudfoundry/bosh-cli/director"
	"github.com/cloudfoundry/bosh-cli/director/directorfakes"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Bosh Scanning", func() {
	var (
		mockCtrl         *gomock.Controller
		boshScan         scanner.Scanner
		targetDeployment *bosh.MockTargetDeployment
		machine          *remotemachine.MockRemoteMachine

		vmInfo     []boshdirector.VMInfo
		systemInfo scantron.SystemInfo

		release1, release2 *directorfakes.FakeRelease
		releaseInfo        []boshdirector.Release

		scanResult scanner.ScanResult
		scanErr    error
		logger scanlog.Logger
		buffer *bytes.Buffer

		fileMatch *scantron.FileMatch
	)

	AfterEach(func() {
		mockCtrl.Finish()
	})

	BeforeEach(func() {
		mockCtrl = gomock.NewController(Test)
		machine = remotemachine.NewMockRemoteMachine(mockCtrl)
		logger = scanlog.NewNopLogger()

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
		machine.EXPECT().Close().Return(nil).Times(1)

		targetDeployment = bosh.NewMockTargetDeployment(mockCtrl)

		vmInfo = []boshdirector.VMInfo{
			{
				JobName: "service",
				ID:      "id",
				IPs:     []string{"10.0.0.1"},
			},
		}
		targetDeployment.EXPECT().ConnectTo(vmInfo[0]).Return(machine).Times(1)

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

		boshScan = scanner.Bosh(targetDeployment)
	})

	JustBeforeEach(func() {
		setupCall := targetDeployment.EXPECT().Setup().Times(1)
		targetDeployment.EXPECT().Name().Return("vm").AnyTimes()
		targetDeployment.EXPECT().VMs().Return(vmInfo).Times(1)
		targetDeployment.EXPECT().Releases().Return(releaseInfo).Times(1)
		targetDeployment.EXPECT().Cleanup().Times(1).After(setupCall)

	})
	Context("when no regex specified", func() {
		It("cleans up the proc_scan binary after the scanning is done", func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(buffer, nil).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
			scanResult, scanErr = boshScan.Scan(fileMatch, logger)
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
			scanResult, scanErr = boshScan.Scan(fileMatch, logger)
		})
	})

	It("returns a report from the deployment", func() {

		machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
		machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(buffer, nil).Times(1)
		machine.EXPECT().DeleteFile("./proc_scan").Times(1)
		scanResult, scanErr = boshScan.Scan(fileMatch, logger)
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
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(buffer, nil).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
		})

		It("all still works", func() {
			scanResult, scanErr = boshScan.Scan(fileMatch, logger)
			Expect(scanErr).ShouldNot(HaveOccurred())
		})
	})

	Context("when uploading the scanning binary fails", func() {
		BeforeEach(func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(errors.New("disaster")).Times(1)
		})

		It("keeps going", func() {
			scanResult, scanErr = boshScan.Scan(fileMatch, logger)
			Expect(scanErr).NotTo(HaveOccurred())
		})
	})

	Context("when running the scanning binary fails", func() {
		BeforeEach(func() {
			machine.EXPECT().UploadFile(gomock.Any(), "./proc_scan").Return(nil).Times(1)
			machine.EXPECT().RunCommand("echo password | sudo -S -- ./proc_scan --context 10.0.0.1 --max 1000").Return(nil, errors.New("disaster")).Times(1)
			machine.EXPECT().DeleteFile("./proc_scan").Times(1)
		})

		It("keeps going", func() {
			scanResult, scanErr = boshScan.Scan(fileMatch, logger)
			Expect(scanErr).NotTo(HaveOccurred())
		})
	})
})
