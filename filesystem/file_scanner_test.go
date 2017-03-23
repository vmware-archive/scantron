package filesystem_test

import (
	"github.com/pivotal-cf/scantron/filesystem"

	"io/ioutil"
	"os"
	"path"
	"syscall"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron"
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

	It("should return empty slice when root is empty", func() {
		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(BeEmpty())
	})

	It("should not detect files not accessible by others", func() {
		createFile(root, 0640)

		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(BeEmpty())
	})

	It("should detect world readable files", func() {
		filePath := createFile(root, 0004)

		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(ConsistOf(scantron.File{Path: filePath}))
	})

	It("should detect world writable files", func() {
		filePath := createFile(root, 0002)

		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(ConsistOf(scantron.File{Path: filePath}))
	})

	It("should detect world executable files", func() {
		filePath := createFile(root, 0001)

		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(ConsistOf(scantron.File{Path: filePath}))
	})

	It("should exclude directories", func() {
		createDir("some-dir", 0755)

		files := filesystem.ScanFilesystem(root, []string{})
		Expect(files).To(BeEmpty())
	})

	It("should exclude files from the exclude list", func() {
		procDir := createDir("proc", 0755)

		createFile(procDir, 0004)

		files := filesystem.ScanFilesystem(root, []string{procDir})
		Expect(files).To(BeEmpty())
	})
})
