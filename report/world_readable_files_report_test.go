package report_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

var _ = Describe("BuildWorldReadableFilesReport", func() {
	var (
		databasePath string
		database     *db.Database
	)

	BeforeEach(func() {
		databaseFile, err := ioutil.TempFile("", "database.db")
		Expect(err).NotTo(HaveOccurred())
		databaseFile.Close()

		databasePath = databaseFile.Name()

		database, err = createTestDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := database.Close()
		Expect(err).NotTo(HaveOccurred())

		err = os.Remove(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	It("shows world-readable configuration files", func() {
		r, err := report.BuildWorldReadableFilesReport(database)
		Expect(err).NotTo(HaveOccurred())

		Expect(r.Header).To(Equal([]string{"Identity", "Path"}))

		Expect(r.Rows).To(HaveLen(2))

		Expect(r.Rows).To(Equal([][]string{
			{"host1", "/var/vcap/data/jobs/world-everything"},
			{"host3", "/var/vcap/data/jobs/world-readable"},
		}))
	})
})
