package netstat_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/netstat"
)

var _ = Describe("NetstatParser", func() {
	It("parses and converts a single line correctly", func() {
		input := `
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1317/java
		`
		Expect(netstat.ParseNetstatOutputForPort(input)).To(Equal([]netstat.NetstatPort{
			{
				CommandName: "java",
				PID:         1317,
				Local: scantron.Port{
					Protocol: "tcp",
					Address:  "127.0.0.1",
					Number:   8080,
					State:    "LISTEN",
				},
				Foreign: scantron.Port{
					Protocol: "tcp",
					Address:  "0.0.0.0",
					Number:   0,
					State:    "LISTEN",
				},
				State: "LISTEN",
			},
		}))
	})

	It("parses and converts multiple lines correctly", func() {
		input := `
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1317/java
udp        0      0 127.0.0.2:8080          0.0.0.0:*               LISTEN      1318/java
		`
		Expect(netstat.ParseNetstatOutputForPort(input)).To(Equal([]netstat.NetstatPort{
			{
				CommandName: "java",
				PID:         1317,
				Local: scantron.Port{
					Protocol: "tcp",
					Address:  "127.0.0.1",
					Number:   8080,
					State:    "LISTEN",
				},
				Foreign: scantron.Port{
					Protocol: "tcp",
					Address:  "0.0.0.0",
					Number:   0,
					State:    "LISTEN",
				},
				State: "LISTEN",
			},
			{
				CommandName: "java",
				PID:         1318,
				Local: scantron.Port{
					Protocol: "udp",
					Address:  "127.0.0.2",
					Number:   8080,
					State:    "LISTEN",
				},
				Foreign: scantron.Port{
					Protocol: "udp",
					Address:  "0.0.0.0",
					Number:   0,
					State:    "LISTEN",
				},
				State: "LISTEN",
			},
		}))
	})

	Context("when the socket state is missing because it is a raw socket", func() {
		It("still parses that", func() {
			input := "udp        0      0 127.0.0.1:53            0.0.0.0:*                           4113/consul"

			Expect(netstat.ParseNetstatOutputForPort(input)).To(Equal([]netstat.NetstatPort{
				{
					CommandName: "consul",
					PID:         4113,
					Local: scantron.Port{
						Protocol: "udp",
						Address:  "127.0.0.1",
						Number:   53,
						State:    "",
					},
					Foreign: scantron.Port{
						Protocol: "udp",
						Address:  "0.0.0.0",
						Number:   0,
						State:    "",
					},
					State: "",
				},
			}))
		})
	})
})
