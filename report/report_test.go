package report_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Report", func() {
	var (
		databasePath string
		database     *db.Database
	)

	BeforeEach(func() {
		hosts := []scanner.ScanResult{
			{
				Job: "host3",
				Services: []scantron.Process{
					{
						CommandName: "command1",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.23",
								Number:  7890,
								TLSInformation: scantron.TLSInformation{
									Certificate: &scantron.Certificate{},
									CipherInformation: scantron.CipherInformation{
										"VersionSSL30": []string{"Just the worst"},
									},
								},
							},
						},
					},
				},
			},
			{
				Job: "host1",
				Services: []scantron.Process{
					{
						CommandName: "command2",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  19999,
							},
						},
					},
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
										"VersionSSL30": []string{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
									},
								},
							},
							{
								State:   "LISTEN",
								Address: "44.44.44.44",
								Number:  7890,
							},
							{
								State:   "LISTEN",
								Address: "127.0.0.1",
								Number:  8890,
								TLSInformation: scantron.TLSInformation{
									Certificate: &scantron.Certificate{},
									CipherInformation: scantron.CipherInformation{
										"VersionTLS12": []string{"Bad Cipher"},
									},
								},
							},
							{
								State:  "ESTABLISHED",
								Number: 7891,
							},
						},
					},
					{
						CommandName: "sshd",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  22,
							},
						},
					},
					{
						CommandName: "rpcbind",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  111,
							},
						},
					},
				},
			},
			{
				Job: "host2",
				Services: []scantron.Process{
					{
						CommandName: "command2",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.22",
								Number:  19999,
								TLSInformation: scantron.TLSInformation{
									Certificate: &scantron.Certificate{},
									CipherInformation: scantron.CipherInformation{
										"VersionTLS12": []string{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
									},
								},
							},
						},
					},
					{
						CommandName: "some-non-root-process",
						User:        "vcap",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.22",
								Number:  12345,
							},
						},
					},
				},
			},
		}

		databaseFile, err := ioutil.TempFile("", "database.db")
		Expect(err).NotTo(HaveOccurred())
		databaseFile.Close()

		databasePath = databaseFile.Name()

		database, err = db.CreateDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())

		err = database.SaveReport(hosts)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := database.Close()
		Expect(err).NotTo(HaveOccurred())

		err = os.Remove(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("BuildRootProcessesReport", func() {
		It("shows externally-accessible processes running as root", func() {
			r, err := report.BuildRootProcessesReport(database)
			Expect(err).NotTo(HaveOccurred())

			Expect(r.Header).To(Equal([]string{"Identity", "Port", "Process Name"}))

			Expect(r.Rows).To(HaveLen(4))

			Expect(r.Rows).To(Equal([][]string{
				{"host1", " 7890", "command1"},
				{"host1", "19999", "command2"},
				{"host2", "19999", "command2"},
				{"host3", " 7890", "command1"},
			}))
		})
	})

	Describe("BuildTLSViolationsReport", func() {
		It("shows processes using non-approved protocols or cipher suites", func() {
			r, err := report.BuildTLSViolationsReport(database)
			Expect(err).NotTo(HaveOccurred())

			Expect(r.Header).To(Equal([]string{"Identity", "Port", "Process Name", "Reason"}))

			Expect(r.Rows).To(HaveLen(3))

			Expect(r.Rows).To(Equal([][]string{
				{"host1", " 7890", "command1", "non-approved protocol(s)"},
				{"host1", " 8890", "command1", "non-approved cipher(s)"},
				{"host3", " 7890", "command1", "non-approved protocol(s)\nnon-approved cipher(s)"},
			}))
		})
	})
})
