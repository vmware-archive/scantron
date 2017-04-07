package filesystem_test

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/filesystem"

	"io/ioutil"
	"os"
	"path"
	"syscall"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FileScanner", func() {
	var (
		umask int
		root  string
	)

	BeforeEach(func() {
		var err error

		root, err = ioutil.TempDir("", "proc-scan-test")
		Expect(err).NotTo(HaveOccurred())

		umask = syscall.Umask(0000)
	})

	AfterEach(func() {
		os.RemoveAll(root)

		syscall.Umask(umask)
	})

	createFile := func(dirPath string, perm os.FileMode) string {
		filePath := path.Join(dirPath, "some-file")

		err := ioutil.WriteFile(filePath, []byte{}, perm)
		Expect(err).NotTo(HaveOccurred())

		return filePath
	}

	createDir := func(dirName string, perm os.FileMode) string {
		dirPath := path.Join(root, dirName)

		err := os.Mkdir(dirPath, 0755)
		Expect(err).NotTo(HaveOccurred())

		return dirPath
	}

	It("does not detect files not accessible by others", func() {
		createFile(root, 0640)

		files, err := filesystem.ScanFilesystem(root, []string{})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(BeEmpty())
	})

	It("detects world readable files", func() {
		filePath := createFile(root, 0004)

		files, err := filesystem.ScanFilesystem(root, []string{})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(ConsistOf(scantron.File{
			Path:        filePath,
			Permissions: 0004,
		}))
	})

	It("detects world writable files", func() {
		filePath := createFile(root, 0002)

		files, err := filesystem.ScanFilesystem(root, []string{})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(ConsistOf(scantron.File{
			Path:        filePath,
			Permissions: 0002,
		}))
	})

	It("detects world executable files", func() {
		filePath := createFile(root, 0001)

		files, err := filesystem.ScanFilesystem(root, []string{})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(ConsistOf(scantron.File{
			Path:        filePath,
			Permissions: 0001,
		}))
	})

	It("excludes directories", func() {
		createDir("some-dir", 0755)

		files, err := filesystem.ScanFilesystem(root, []string{})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(BeEmpty())
	})

	It("excludes files from the exclude list", func() {
		procDir := createDir("proc", 0755)

		createFile(procDir, 0004)

		files, err := filesystem.ScanFilesystem(root, []string{procDir})
		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(BeEmpty())
	})

	It("returns an error when it fails to walk the filesystem", func() {
		_, err := filesystem.ScanFilesystem("/poop", []string{})
		Expect(err).To(HaveOccurred())
	})
})
