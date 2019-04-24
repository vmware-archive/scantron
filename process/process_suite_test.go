package process_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestUse(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Process Suite")
}
