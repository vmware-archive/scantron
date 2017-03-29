package remotemachine_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestRemotemachine(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Remote Machine Suite")
}
