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
				PID: 1317,
				Port: scantron.Port{
					Protocol: "tcp",
					Address:  "127.0.0.1",
					Number:   8080,
					State:    "LISTEN",
				},
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
				PID: 1317,
				Port: scantron.Port{
					Protocol: "tcp",
					Address:  "127.0.0.1",
					Number:   8080,
					State:    "LISTEN",
				},
			},
			{
				PID: 1318,
				Port: scantron.Port{
					Protocol: "udp",
					Address:  "127.0.0.2",
					Number:   8080,
					State:    "LISTEN",
				},
			},
		}))
	})

	Context("when the socket state is missing because it is a raw socket", func() {
		It("still parses that", func() {
			input := "udp        0      0 127.0.0.1:53            0.0.0.0:*                           4113/consul"

			Expect(netstat.ParseNetstatOutputForPort(input)).To(Equal([]netstat.NetstatPort{
				{
					PID: 4113,
					Port: scantron.Port{
						Protocol: "udp",
						Address:  "127.0.0.1",
						Number:   53,
						State:    "",
					},
				},
			}))
		})
	})
})
