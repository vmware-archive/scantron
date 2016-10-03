package manifest_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/manifest"
)

var _ = Describe("Manifest", func() {
	host := manifest.Spec{
		Prefix: "a-host",
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

	Describe("getting the expected ports for a host", func() {
		It("gets all of the ports across every process", func() {
			Expect(host.ExpectedPorts()).To(ConsistOf(
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

	Describe("getting the expected processes for a host", func() {
		It("gets all of the commands across every process", func() {
			Expect(host.ExpectedCommands()).To(ConsistOf(
				"command-1",
				"command-2",
			))
		})
	})
})
