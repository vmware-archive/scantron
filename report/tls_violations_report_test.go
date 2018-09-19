package report_test

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

var _ = Describe("BuildTLSViolationsReport", func() {
	var (
		databasePath, tmpdir string
		database             *db.Database
	)

	BeforeEach(func() {
		var err error
		tmpdir, err = ioutil.TempDir("", "report-test")
		Expect(err).NotTo(HaveOccurred())
		databasePath = filepath.Join(tmpdir, "db.db")

		database, err = createTestDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := database.Close()
		Expect(err).NotTo(HaveOccurred())

		err = os.RemoveAll(tmpdir)
		Expect(err).NotTo(HaveOccurred())
	})

	It("shows processes using non-approved protocols or cipher suites", func() {
		r, err := report.BuildTLSViolationsReport(database)
		Expect(err).NotTo(HaveOccurred())

		Expect(r.Title).To(Equal("Processes using non-approved SSL/TLS settings:"))

		Expect(r.Header).To(Equal([]string{
			"Identity",
			"Port",
			"Process Name",
			"Non-approved Protocol(s)",
			"Non-approved Cipher(s)",
		}))

		Expect(r.Rows).To(HaveLen(3))
		Expect(r.Rows).To(ConsistOf(
			[]string{"host1", "7890", "command1", "VersionSSL30", ""},
			[]string{"host1", "8890", "command1", "", "Bad Cipher"},
			[]string{"host3", "7890", "command1", "VersionSSL30", "Just the worst"},
		))
	})
})
