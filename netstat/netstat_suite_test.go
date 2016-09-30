package netstat_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestNetstat(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netstat Suite")
}
