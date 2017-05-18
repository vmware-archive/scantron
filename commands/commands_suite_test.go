package commands_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"os/exec"
	"testing"

	"github.com/onsi/gomega/gexec"
)

func TestCmd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Commands Suite")
}

var commandPath string

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	commandPath, err = gexec.Build("github.com/pivotal-cf/scantron/cmd/scantron")
	Expect(err).NotTo(HaveOccurred())

	return []byte(commandPath)
}, func(data []byte) {
	commandPath = string(data)
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	gexec.CleanupBuildArtifacts()
})

func runCommand(args ...string) *gexec.Session {
	cmd := exec.Command(commandPath, args...)

	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	<-session.Exited

	return session
}
