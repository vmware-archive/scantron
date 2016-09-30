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
	Context("When there is an unexpected port in the report", func() {
		var (
			db     *commands.Database
			tmpdir string
			mani   manifest.Manifest
		)

		BeforeEach(func() {
			mani = manifest.Manifest{
				Hosts: []manifest.Host{
					{
						Name: "host1",
						Processes: []manifest.Process{
							{
								Command: "command1",
								User:    "root",
								Ports:   []manifest.Port{1234},
							},
						},
					},
				},
			}

			var err error
			tmpdir, err = ioutil.TempDir("", "audit")

			db, err = commands.CreateDatabase(filepath.Join(tmpdir, "database.db"))
			Expect(err).NotTo(HaveOccurred())

			hosts := []scanner.ScanResult{
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
							},
						},
					},
				},
			}

			err = db.SaveReport(hosts)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			db.Close()
			os.RemoveAll(tmpdir)
		})

		It("returns a result showing the unexpected port", func() {
			result, err := audit.Audit(db.DB(), mani)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Hosts).To(HaveLen(1))
			Expect(result.Hosts["host1"].UnexpectedPorts).To(ConsistOf(audit.Port(2345)))
		})
	})
})
