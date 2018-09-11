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

var _ = Describe("BuildRootProcessesReport", func() {
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

	It("shows externally-accessible processes running as root", func() {
		r, err := report.BuildRootProcessesReport(database)
		Expect(err).NotTo(HaveOccurred())

		Expect(r.Title).To(Equal("Externally-accessible processes running as root:"))
		Expect(r.Header).To(Equal([]string{"Identity", "Port", "Process Name"}))
		Expect(r.Rows).To(HaveLen(6))
		Expect(r.Rows).To(Equal([][]string{
			{"host1", "7890", "command1"},
			{"host1", "19999", "command2"},
			{"host2", "19999", "command2"},
			{"host3", "7890", "command1"},
			{"winhost1", "19998", "command.exe"},
			{"winhost1", "19999", "command2.exe"},
		}))
	})
})
