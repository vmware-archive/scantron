package report_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

var _ = Describe("BuildInsecureSshKeyReport", func() {
	var (
		database     *db.Database
		databasePath string
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

	It("shows insecure and duplicate ssh keys", func() {
		r, err := report.BuildInsecureSshKeyReport(database)
		Expect(err).NotTo(HaveOccurred())

		Expect(r.Title).To(Equal("Duplicate SSH keys:"))
		Expect(r.Header).To(Equal([]string{"Identity"}))
		Expect(r.Rows).To(HaveLen(2))
		Expect(r.Rows).To(Equal([][]string{
			{"host1"},
			{"host3"},
		}))
	})
})
