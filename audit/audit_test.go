package audit_test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/audit"
	"github.com/pivotal-cf/scantron/commands"
	"github.com/pivotal-cf/scantron/manifest"
	"github.com/pivotal-cf/scantron/scanner"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Audit", func() {
	var (
		db     *commands.Database
		tmpdir string

		hosts []scanner.ScanResult
		mani  manifest.Manifest
	)

	BeforeEach(func() {
		var err error
		tmpdir, err = ioutil.TempDir("", "audit")
		Expect(err).NotTo(HaveOccurred())

		db, err = commands.CreateDatabase(filepath.Join(tmpdir, "database.db"))
		Expect(err).NotTo(HaveOccurred())
	})

	JustBeforeEach(func() {
		err := db.SaveReport(hosts)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		db.Close()
		os.RemoveAll(tmpdir)
	})

	Context("when there is only one report in the db", func() {
		Context("when the manifest and report match", func() {
			BeforeEach(func() {
				mani = manifest.Manifest{
					Specs: []manifest.Spec{
						{
							Prefix: "host1",
							Processes: []manifest.Process{
								{
									Command: "command1",
									User:    "root",
									Ports:   []manifest.Port{1234, 6789},
								},
							},
						},
						{
							Prefix: "host2",
							Processes: []manifest.Process{
								{
									Command: "command2",
									User:    "vcap",
									Ports:   []manifest.Port{5432},
								},
							},
						},
					},
				}

				hosts = []scanner.ScanResult{
					{
						Job: "host1",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
									{
										Number: 6789,
										State:  "LISTEN",
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
								User:        "vcap",
								Ports: []scantron.Port{
									{
										Number: 5432,
										State:  "LISTEN",
									},
								},
							},
						},
					},
				}
			})

			It("returns a results that says everything is ok", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeTrue())
			})
		})

		Context("when there is an missing and extra host in the report", func() {
			BeforeEach(func() {
				mani = manifest.Manifest{
					Specs: []manifest.Spec{
						{
							Prefix: "host1",
							Processes: []manifest.Process{
								{
									Command: "command1",
									User:    "root",
									Ports:   []manifest.Port{1234},
								},
							},
						},
						{
							Prefix: "host3",
							Processes: []manifest.Process{
								{
									Command: "command3",
									User:    "root",
									Ports:   []manifest.Port{1234},
								},
							},
						},
					},
				}

				hosts = []scanner.ScanResult{
					{
						Job: "host1-1234567",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
								},
							},
						},
					},
					{
						Job: "host2-123456",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
								},
							},
						},
					},
				}
			})

			It("returns a result showing the extra or missing host", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeFalse())
				Expect(result.ExtraHosts).To(ConsistOf("host2-123456"))
				Expect(result.MissingHostType).To(ConsistOf("host3"))
			})
		})

		Context("when there is a missing process in the report", func() {
			BeforeEach(func() {
				mani = manifest.Manifest{
					Specs: []manifest.Spec{
						{
							Prefix: "host1",
							Processes: []manifest.Process{
								{
									Command: "command1",
									User:    "root",
									Ports:   []manifest.Port{1234},
								},
								{
									Command: "command2",
									User:    "root",
									Ports:   []manifest.Port{1234},
								},
							},
						},
					},
				}

				hosts = []scanner.ScanResult{
					{
						Job: "host1",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
								},
							},
						},
					},
				}
			})

			It("returns a result showing the missing process", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeFalse())
				Expect(result.Hosts).To(HaveKey("host1"))
				Expect(result.Hosts["host1"].MissingProcesses).To(ConsistOf("command2"))
			})
		})

		Context("when there is an unexpected or missing port in the report", func() {
			BeforeEach(func() {
				mani = manifest.Manifest{
					Specs: []manifest.Spec{
						{
							Prefix: "host1",
							Processes: []manifest.Process{
								{
									Command: "command1",
									User:    "root",
									Ports:   []manifest.Port{1234, 80},
								},
								{
									Command: "command2",
									User:    "root",
									Ignore:  true,
								},
							},
						},
					},
				}

				hosts = []scanner.ScanResult{
					{
						Job: "host1",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
									{
										Number: 2345,
										State:  "LISTEN",
									},
									{
										Number:  3456,
										State:   "LISTEN",
										Address: "127.0.0.1",
									},
									{
										Number: 234,
										State:  "CLOSE_WAIT",
									},
								},
							},
							{
								CommandName: "command2",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 57332,
										State:  "LISTEN",
									},
								},
							},
						},
					},
				}
			})

			It("returns a result showing the unexpected port", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeFalse())
				Expect(result.Hosts).To(HaveKey("host1"))
				Expect(result.Hosts["host1"].UnexpectedPorts).To(ConsistOf(audit.Port(2345)))
			})

			It("returns a result showing the missing port", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeFalse())
				Expect(result.Hosts).To(HaveKey("host1"))
				Expect(result.Hosts["host1"].MissingPorts).To(ConsistOf(audit.Port(80)))
			})
		})

		Context("when one of processes is running with incorrect user", func() {
			BeforeEach(func() {
				mani = manifest.Manifest{
					Specs: []manifest.Spec{
						{
							Prefix: "host1",
							Processes: []manifest.Process{
								{
									Command: "command1",
									User:    "vcap",
									Ports:   []manifest.Port{1234},
								},
							},
						},
					},
				}

				hosts = []scanner.ScanResult{
					{
						Job: "host1",
						Services: []scantron.Process{
							{
								CommandName: "command1",
								User:        "root",
								Ports: []scantron.Port{
									{
										Number: 1234,
										State:  "LISTEN",
									},
								},
							},
						},
					},
				}
			})

			It("returns a result showing incorrect values", func() {
				result, err := audit.Audit(db.DB(), mani)
				Expect(err).NotTo(HaveOccurred())

				Expect(result.OK()).To(BeFalse())
				Expect(result.Hosts).To(HaveKey("host1"))
				Expect(result.Hosts["host1"].MismatchedProcesses).To(ConsistOf(audit.MismatchedProcess{
					Command:  "command1",
					Field:    "user",
					Actual:   "root",
					Expected: "vcap",
				}))
			})
		})
	})

	Context("when there are multiple reports in the db", func() {
		var (
			latestHosts []scanner.ScanResult
		)

		JustBeforeEach(func() {
			err := db.SaveReport(latestHosts)
			Expect(err).NotTo(HaveOccurred())
		})

		BeforeEach(func() {
			mani = manifest.Manifest{
				Specs: []manifest.Spec{
					{
						Prefix: "latest-host-1",
						Processes: []manifest.Process{
							{
								Command: "command1",
								User:    "root",
								Ports:   []manifest.Port{1234, 6789},
							},
						},
					},
					{
						Prefix: "latest-host-2",
						Processes: []manifest.Process{
							{
								Command: "command2",
								User:    "vcap",
								Ports:   []manifest.Port{5432},
							},
						},
					},
				},
			}

			hosts = []scanner.ScanResult{
				{
					Job: "not-in-question-host",
					Services: []scantron.Process{
						{
							CommandName: "command1",
							User:        "root",
							Ports: []scantron.Port{
								{
									Number: 1234,
									State:  "LISTEN",
								},
								{
									Number: 6789,
									State:  "LISTEN",
								},
							},
						},
					},
				},
			}

			latestHosts = []scanner.ScanResult{
				{
					Job: "latest-host-1",
					Services: []scantron.Process{
						{
							CommandName: "command1",
							User:        "root",
							Ports: []scantron.Port{
								port(1234),
								port(6789),
							},
						},
					},
				},
				{
					Job: "latest-host-2",
					Services: []scantron.Process{
						{
							CommandName: "command2",
							User:        "vcap",
							Ports: []scantron.Port{
								port(5432),
							},
						},
					},
				},
			}
		})

		It("audits the latest report against the given manifest", func() {
			result, err := audit.Audit(db.DB(), mani)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.OK()).To(BeTrue())
		})
	})
})
