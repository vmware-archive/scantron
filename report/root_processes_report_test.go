package report_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

var _ = Describe("BuildRootProcessesReport", func() {
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
