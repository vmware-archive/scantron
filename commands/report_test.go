package commands_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Report", func() {
	var (
		databasePath string
		database     *db.Database
	)

	BeforeEach(func() {
		databaseFile, err := ioutil.TempFile("", "database.db")
		Expect(err).NotTo(HaveOccurred())
		databaseFile.Close()

		databasePath = databaseFile.Name()

		database, err = db.CreateDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := database.Close()
		Expect(err).NotTo(HaveOccurred())

		err = os.Remove(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when there are violations", func() {
		BeforeEach(func() {
			hosts := []scanner.ScanResult{
				{
					Job: "host1",
					Files: []scantron.File{
						{
							Path:        "/var/vcap/data/jobs/my.cnf",
							Permissions: 0644,
						},
					},
					Services: []scantron.Process{
						{
							CommandName: "command1",
							User:        "root",
							Ports: []scantron.Port{
								{
									State:   "LISTEN",
									Address: "10.0.5.21",
									Number:  7890,
									TLSInformation: scantron.TLSInformation{
										Certificate: &scantron.Certificate{},
										CipherInformation: scantron.CipherInformation{
											"VersionSSL30": []string{"bad cipher"},
										},
									},
								},
							},
						},
					},
				},
			}

			err := database.SaveReport(hosts)
			Expect(err).NotTo(HaveOccurred())
		})

		It("shows externally-accessible processes running as root", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(1))

			Expect(session.Out).To(Say("Externally-accessible processes running as root:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|\s+PORT\s+\|\s+PROCESS NAME\s+\|`))

			Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+7890\s+\|\s+command1\s+\|`))
		})

		It("shows processes using non-approved protocols or cipher suites", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(1))

			Expect(session.Out).To(Say("Processes using non-approved protocols or cipher suites:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|\s+PORT\s+\|\s+PROCESS NAME\s+\|\s+REASON\s+\|`))

			Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+7890\s+\|\s+command1\s+\|\s+non-approved protocol\(s\)\s+\|`))
			Expect(session.Out).To(Say(`\|\s+\|\s+\|\s+\|\s+non-approved cipher\(s\)\s+\|`))
		})

		It("shows world-readable files", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(1))

			Expect(session.Out).To(Say("World-readable files:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|\s+PATH\s+\|`))

			Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+/var/vcap/data/jobs/my.cnf\s+\|`))
		})
	})

	Context("when there are no violations", func() {
		BeforeEach(func() {
			hosts := []scanner.ScanResult{
				{
					Job: "host1",
					Services: []scantron.Process{
						{
							CommandName: "command1",
							User:        "vcap",
							Ports: []scantron.Port{
								{
									State:   "LISTEN",
									Address: "10.0.5.21",
									Number:  7890,
									TLSInformation: scantron.TLSInformation{
										Certificate: &scantron.Certificate{},
										CipherInformation: scantron.CipherInformation{
											"VersionTLS12": []string{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
										},
									},
								},
							},
						},
					},
				},
			}

			err := database.SaveReport(hosts)
			Expect(err).NotTo(HaveOccurred())
		})

		It("exits without error", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(0))

			Expect(session.Out).To(Say("Externally-accessible processes running as root:"))
			Expect(session.Out).To(Say("Processes using non-approved protocols or cipher suites:"))
		})
	})
})
