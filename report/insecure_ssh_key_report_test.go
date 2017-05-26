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

var _ = Describe("BuildInsecureSshKeyReport", func() {
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
