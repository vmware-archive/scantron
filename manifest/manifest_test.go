package manifest_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/manifest"
)

var _ = Describe("Manifest", func() {
	Describe("getting the expected ports for a host", func() {
		It("gets all of the ports across every process", func() {
			host := manifest.Host{
				Name: "a-host",
				Processes: []manifest.Process{
					{
						Command: "command-1",
						Ports:   []manifest.Port{1, 6, 8, 2},
					},
					{
						Command: "command-2",
						Ports:   []manifest.Port{93, 235, 2493},
					},
				},
			}

			ports := host.ExpectedPorts()
			Expect(ports).To(ConsistOf(
				manifest.Port(1),
				manifest.Port(2),
				manifest.Port(6),
				manifest.Port(8),
				manifest.Port(93),
				manifest.Port(235),
				manifest.Port(2493),
			))
		})
	})
})
