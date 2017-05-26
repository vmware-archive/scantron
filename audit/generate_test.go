package audit_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/audit"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/manifest"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Generate", func() {
	var (
		database *db.Database
		tmpdir   string

		writer *bytes.Buffer
		hosts  scanner.ScanResult
	)

	BeforeEach(func() {
		writer = &bytes.Buffer{}
		var err error
		tmpdir, err = ioutil.TempDir("", "audit")
		Expect(err).NotTo(HaveOccurred())

		database, err = db.CreateDatabase(filepath.Join(tmpdir, "database.db"))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		database.Close()
		os.RemoveAll(tmpdir)
	})

	JustBeforeEach(func() {
		err := database.SaveReport(hosts)
		Expect(err).NotTo(HaveOccurred())
		err = audit.GenerateManifest(writer, database.DB())
		Expect(err).NotTo(HaveOccurred())
	})

	Context("when hosts is empty", func() {
		BeforeEach(func() {
			hosts = scanner.ScanResult{
				JobResults: []scanner.JobResult{},
			}
		})

		It("shows empty manifest", func() {
			var m manifest.Manifest
			err := yaml.Unmarshal(writer.Bytes(), &m)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Specs).To(BeEmpty())
		})
	})

	Context("when a single host exists", func() {
		BeforeEach(func() {
			hosts = scanner.ScanResult{
				JobResults: []scanner.JobResult{
					{
						Job: "My Host",
						Services: []scantron.Process{
							{
								CommandName: "some process",
								User:        "some user",
								Ports: []scantron.Port{
									port(22),
									port(80),
								},
							},
							{
								CommandName: "another process",
								User:        "another user",
								Ports: []scantron.Port{
									port(443),
									port(8080),
									{
										Number:  1024,
										Address: "127.0.0.1",
									},
									{
										Number: 1024,
										State:  "ESTABLISHED",
									},
									{
										Number: 1012,
										State:  "CLOSE_WAIT",
									},
								},
							},
							{
								CommandName: "non-listening process",
								User:        "non-listening user",
							},
							{
								CommandName: "only-bad-ports process",
								User:        "only-bad-ports user",
								Ports: []scantron.Port{
									{
										Number:  1024,
										Address: "127.0.0.1",
									},
									{
										Number: 1024,
										State:  "ESTABLISHED",
									},
									{
										Number: 1012,
										State:  "CLOSE_WAIT",
									},
								},
							},
						},
					},
				},
			}
		})

		It("shows host with services and processes", func() {
			var m manifest.Manifest
			err := yaml.Unmarshal(writer.Bytes(), &m)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Specs).To(HaveLen(1))
			Expect(m.Specs[0].Prefix).To(Equal(hosts.JobResults[0].Job))
			Expect(m.Specs[0].Processes).To(ConsistOf(
				manifest.Process{
					Command: hosts.JobResults[0].Services[0].CommandName,
					User:    hosts.JobResults[0].Services[0].User,
					Ports:   []manifest.Port{22, 80},
				},
				manifest.Process{
					Command: hosts.JobResults[0].Services[1].CommandName,
					User:    hosts.JobResults[0].Services[1].User,
					Ports:   []manifest.Port{443, 8080},
				},
			))
		})

		It("does not show the ignore_ports field", func() {
			Expect(writer.String()).NotTo(ContainSubstring("ignore_ports"))
		})
	})

	Context("when multiple hosts exists", func() {
		BeforeEach(func() {
			hosts = scanner.ScanResult{
				JobResults: []scanner.JobResult{
					{
						Job: "My Host",
						Services: []scantron.Process{
							{
								CommandName: "some process",
								User:        "some user",
								Ports: []scantron.Port{
									port(22),
									port(80),
								},
							},
						},
					},
					{
						Job: "My Other Host",
						Services: []scantron.Process{
							{
								CommandName: "some other process",
								User:        "some other user",
								Ports: []scantron.Port{
									port(443),
									port(8080),
								},
							},
						},
					},
				},
			}
		})

		It("shows host with processes", func() {
			var m manifest.Manifest
			err := yaml.Unmarshal(writer.Bytes(), &m)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Specs).To(HaveLen(2))
			Expect(m.Specs[0].Prefix).To(Equal(hosts.JobResults[0].Job))
			Expect(m.Specs[0].Processes).To(ConsistOf(manifest.Process{
				Command: hosts.JobResults[0].Services[0].CommandName,
				User:    hosts.JobResults[0].Services[0].User,
				Ports:   []manifest.Port{22, 80},
			}))

			Expect(m.Specs[1].Prefix).To(Equal(hosts.JobResults[1].Job))
			Expect(m.Specs[1].Processes).To(ConsistOf(manifest.Process{
				Command: hosts.JobResults[1].Services[0].CommandName,
				User:    hosts.JobResults[1].Services[0].User,
				Ports:   []manifest.Port{443, 8080},
			}))
		})
	})
})

func port(number int) scantron.Port {
	return scantron.Port{
		Number: number,
		State:  "LISTEN",
	}
}
