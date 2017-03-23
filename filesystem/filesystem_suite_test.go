package filesystem_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestFilesystem(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Filesystem Suite")
}
