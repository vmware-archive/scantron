package scanner_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var Test *testing.T // GinkgoT() panics if mock expectation fails in goroutine
func TestScanner(t *testing.T) {
	Test = t
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}
