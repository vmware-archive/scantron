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

var _ = Describe("BuildWorldReadableFilesReport", func() {
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

	It("shows world-readable configuration files", func() {
		r, err := report.BuildWorldReadableFilesReport(database)
		Expect(err).NotTo(HaveOccurred())

		Expect(r.Title).To(Equal("World-readable files:"))
		Expect(r.Header).To(Equal([]string{"Identity", "Path"}))
		Expect(r.Rows).To(HaveLen(2))
		Expect(r.Rows).To(Equal([][]string{
			{"host1", "/var/vcap/data/jobs/world-everything"},
			{"host3", "/var/vcap/data/jobs/world-readable"},
		}))
	})
})
