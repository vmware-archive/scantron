package commands_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"

	"path/filepath"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Report", func() {
	var (
		databasePath, tmpdir string
		database             *db.Database
	)

	BeforeEach(func() {
		var err error
		tmpdir, err = ioutil.TempDir("", "report-test")
		Expect(err).NotTo(HaveOccurred())
		databasePath = filepath.Join(tmpdir, "db.db")

		database, err = db.CreateDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := database.Close()
		Expect(err).NotTo(HaveOccurred())

		err = os.RemoveAll(tmpdir)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when there are violations", func() {
		BeforeEach(func() {
			hosts := scanner.ScanResult{
				JobResults: []scanner.JobResult{
					{
						Job: "host1",
						Files: []scantron.File{
							{
								Path:        "/var/vcap/data/jobs/my.cnf",
								Permissions: 0644,
							},
						},
						SSHKeys: []scantron.SSHKey{
							{
								Type: "ssh-rsa",
								Key:  "key-1",
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
					{
						Job: "host2",
						SSHKeys: []scantron.SSHKey{
							{
								Type: "ssh-rsa",
								Key:  "key-1",
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

			Expect(session.Out).To(Say("Processes using non-approved SSL/TLS settings:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|\s+PORT\s+\|\s+PROCESS NAME\s+\|\s+NON-APPROVED PROTOCOL\(S\)\s+\|\s+NON-APPROVED CIPHER\(S\)\s+\|`))
			Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+7890\s+\|\s+command1\s+\|\s+VersionSSL30\s+\|\s+bad cipher\s+\|`))
			Expect(session.Out).To(Say("If this is not an internal endpoint then please check with your PM and the security team before applying this change. This change is not backwards compatible."))
		})

		It("shows world-readable files", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(1))

			Expect(session.Out).To(Say("World-readable files:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|\s+PATH\s+\|`))

			Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+/var/vcap/data/jobs/my.cnf\s+\|`))
		})

		It("shows hosts with duplicate ssh keys", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(1))
			Expect(session.Out).To(Say("Duplicate SSH keys:"))
			Expect(session.Out).To(Say(`\|\s+IDENTITY\s+\|`))

			Expect(session.Out).To(Say(`\|\s+host1\s+\|`))
			Expect(session.Out).To(Say(`\|\s+host2\s+\|`))
		})

		Context("and the csv flag is provided", func() {
			var (
				path string
				err  error
			)

			BeforeEach(func() {
				var err error

				path, err = ioutil.TempDir("", "csv-export")
				Expect(err).NotTo(HaveOccurred())

				err = os.RemoveAll(path)
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				err = os.RemoveAll(path)
				Expect(err).NotTo(HaveOccurred())
			})

			It("outputs root process results to csv", func() {
				session := runCommand("report", "--database", databasePath, "--csv", path)
				Expect(session).To(Exit(1))

				result, err := ioutil.ReadFile(filepath.Join(path, "root_process_report.csv"))
				Expect(err).NotTo(HaveOccurred())

				Expect(string(result)).To(ContainSubstring("Identity,Port,Process Name"))
				Expect(string(result)).To(ContainSubstring("host1,7890,command1"))

				result, err = ioutil.ReadFile(filepath.Join(path, "tls_violation_report.csv"))
				Expect(err).NotTo(HaveOccurred())

				Expect(string(result)).To(ContainSubstring("Identity,Port,Process Name,Non-approved Protocol(s),Non-approved Cipher(s)"))
				Expect(string(result)).To(ContainSubstring("host1,7890,command1,VersionSSL30,bad cipher"))

				result, err = ioutil.ReadFile(filepath.Join(path, "world_readable_files_report.csv"))
				Expect(err).NotTo(HaveOccurred())

				Expect(string(result)).To(ContainSubstring("Identity,Path"))
				Expect(string(result)).To(ContainSubstring("host1,/var/vcap/data/jobs/my.cnf"))

				result, err = ioutil.ReadFile(filepath.Join(path, "insecure_sshkey_report.csv"))
				Expect(err).NotTo(HaveOccurred())

				Expect(string(result)).To(ContainSubstring("Identity"))
				Expect(string(result)).To(ContainSubstring("host1"))
			})
		})
	})

	Context("when there are no violations", func() {
		BeforeEach(func() {
			hosts := scanner.ScanResult{
				JobResults: []scanner.JobResult{
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
				},
			}

			err := database.SaveReport(hosts)
			Expect(err).NotTo(HaveOccurred())
		})

		It("exits without error", func() {
			session := runCommand("report", "--database", databasePath)

			Expect(session).To(Exit(0))

			Expect(session.Out).To(Say("Externally-accessible processes running as root:"))
			Expect(session.Out).To(Say("Processes using non-approved SSL/TLS settings:"))
		})
	})
})
