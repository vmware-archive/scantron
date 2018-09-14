package filesystem_test

import (
  "github.com/pivotal-cf/scantron/filesystem"
  "github.com/pivotal-cf/scantron/scanlog"
  "io/ioutil"
  "os"
  "path"
  "syscall"

  . "github.com/onsi/ginkgo"
  . "github.com/onsi/gomega"
)

var _ = Describe("FileWalker", func() {
  var (
    umask int
    root string
    excludedPaths []string
  )
  var (
    subject filesystem.FileWalker
  )

  createSubject := func() {
    config := filesystem.FileConfig{
      RootPath:      root,
      ExcludedPaths: excludedPaths,
    }
    subject = filesystem.NewWalker(config, scanlog.NewNopLogger())
  }

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

  BeforeEach(func() {
    var err error
    root, err = ioutil.TempDir("", "proc-scan-test")
    Expect(err).NotTo(HaveOccurred())
    umask = syscall.Umask(0000)

    createSubject()
  })

  AfterEach(func() {
    os.RemoveAll(root)
    syscall.Umask(umask)
  })

  It("detects files", func() {
    filePath := createFile(root, 0004)

    files, err := subject.Walk()
    Expect(err).NotTo(HaveOccurred())

    stat, err := os.Stat(filePath)
    Expect(err).NotTo(HaveOccurred())

    Expect(files).To(ConsistOf(filesystem.WalkedFile{
      Path: filePath,
      Info: stat,
    }))
  })

  It("does not record directories", func() {
    createDir("some-dir", 0755)

    files, err := subject.Walk()
    Expect(err).NotTo(HaveOccurred())

    Expect(files).To(BeEmpty())
  })

  It("excludes files from the exclude list", func() {
    procDir := createDir("proc", 0755)
    createFile(procDir, 0004)

    excludedPaths = []string{procDir}
    createSubject()

    files, err := subject.Walk()
    Expect(err).NotTo(HaveOccurred())

    Expect(files).To(BeEmpty())
  })

  It("returns an error when it fails to walk the filesystem", func() {
    root = "/doesnotexist"
    createSubject()

    _, err := subject.Walk()
    Expect(err).To(HaveOccurred())
  })
})
