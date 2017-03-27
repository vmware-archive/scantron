package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/gexec"

	"os/exec"
	"testing"
)

func TestCredAlertCli(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CLI Suite")
}

var scantronPath string

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	scantronPath, err = gexec.Build("github.com/pivotal-cf/scantron/cmd/scantron")
	Expect(err).NotTo(HaveOccurred())

	return []byte(scantronPath)
}, func(data []byte) {
	scantronPath = string(data)
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

func runCommand(args ...string) *gexec.Session {
	cmd := exec.Command(scantronPath, args...)

	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	<-session.Exited

	return session
}
