package tlsscan_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestTlsscan(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Scan Suite")
}
