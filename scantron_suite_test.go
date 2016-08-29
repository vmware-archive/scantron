package scantron_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestScantron(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scantron Suite")
}
