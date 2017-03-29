package remotemachine_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron/remotemachine"
)

var _ = Describe("BestScanAddress", func() {
	It("will pick the private address if it exists (10.*.*.*)", func() {
		addresses := []string{
			"203.0.113.1",
			"10.0.2.4",
		}

		best := remotemachine.BestAddress(addresses)
		Expect(best).To(Equal("10.0.2.4"))
	})

	It("gives up and picks the first one if none of the addresses are private", func() {
		addresses := []string{
			"203.0.113.2",
			"203.0.113.1",
		}

		best := remotemachine.BestAddress(addresses)
		Expect(best).To(Equal("203.0.113.2"))
	})

	It("panics if the input list is empty", func() {
		Expect(func() {
			remotemachine.BestAddress([]string{})
		}).To(Panic())
	})
})
