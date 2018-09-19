package filesystem_test

import (
 "github.com/pivotal-cf/scantron"
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
   contentRegex []string
   pathRegex []string
   subject filesystem.FileWalker
 )

 createSubject := func() {
   config := filesystem.FileConfig{
     RootPath:      root,
     ExcludedPaths: excludedPaths,
   }
   subject, _ = filesystem.NewWalker(
     config,
     scantron.FileMatch{
       pathRegex,
       contentRegex,
       1000,
     },
     scanlog.NewNopLogger())
 }

 createFile := func(dirPath string, content string) string {
   filePath := path.Join(dirPath, "some-file")

   err := ioutil.WriteFile(filePath, []byte(content), 0600)
   Expect(err).NotTo(HaveOccurred())

   return filePath
 }

 createDir := func(dirName string) string {
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
  filePath := createFile(root, "data")

  files, err := subject.Walk()
  Expect(err).NotTo(HaveOccurred())

  Expect(files).To(HaveLen(1))
  Expect(files[0].Path).To(Equal(filePath))
  Expect(files[0].RegexMatches).To(BeNil())
 })

 It("does not record path matches if the content regex does not match", func() {
   contentRegex = []string{"valuable"}
   pathRegex = []string{"interesting"}
   createSubject()
   procDir := createDir("interesting")
   filePath := createFile(procDir, "data")

   files, err := subject.Walk()
   Expect(err).NotTo(HaveOccurred())

   Expect(files).To(HaveLen(1))
   Expect(files[0].Path).To(Equal(filePath))
   Expect(files[0].RegexMatches).To(BeNil())
 })

 It("does record regex matches if both path and content match", func() {
   contentRegex = []string{"valuable"}
   pathRegex = []string{"interesting"}
   createSubject()
   procDir := createDir("interesting")
   filePath := createFile(procDir, "valuable")

   files, err := subject.Walk()
   Expect(err).NotTo(HaveOccurred())

   Expect(files).To(HaveLen(1))
   Expect(files[0].Path).To(Equal(filePath))
   Expect(files[0].RegexMatches).To(ConsistOf(
     scantron.RegexMatch {
         PathRegex: "interesting",
         ContentRegex: "valuable",
     },

   ))
 })

 It("does record regex matches if content matches and no path regex supplied", func() {
   contentRegex = []string{"valuable"}
   pathRegex = []string{}
   createSubject()
   procDir := createDir("anywhere")
   filePath := createFile(procDir, "valuable")

   files, err := subject.Walk()
   Expect(err).NotTo(HaveOccurred())

   Expect(files).To(HaveLen(1))
   Expect(files[0].Path).To(Equal(filePath))
   Expect(files[0].RegexMatches).To(ConsistOf(
     scantron.RegexMatch {
         PathRegex: "",
         ContentRegex: "valuable",
     },

   ))
 })

 It("does not record directories", func() {
  createDir("some-dir")

  files, err := subject.Walk()
  Expect(err).NotTo(HaveOccurred())

  Expect(files).To(BeEmpty())
 })

 It("excludes files from the exclude list", func() {
  procDir := createDir("proc")
  createFile(procDir, "data")

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
