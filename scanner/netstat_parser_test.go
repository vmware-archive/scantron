package scanner_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("NetstatParser", func() {
	It("ignores a non-line", func() {
		input := `
this is a line of text that is not right
`
		Expect(scanner.ParseNetstatOutput(input)).To(Equal([]scanner.NetstatInfo{}))
	})

	It("parses a single line correctly", func() {
		input := `
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1317/java
		`
		Expect(scanner.ParseNetstatOutput(input)).To(Equal([]scanner.NetstatInfo{
			{
				CommandName:    "java",
				ID:             "1317",
				LocalAddress:   "127.0.0.1:8080",
				ForeignAddress: "0.0.0.0:*",
				State:          "LISTEN",
				Protocol:       "tcp",
			},
		}))
	})

	It("parses and converts a single line correctly", func() {
		input := `
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1317/java
		`
		Expect(scanner.ParseNetstatOutputForPort(input)).To(Equal([]scanner.NetstatPort{
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
		Expect(scanner.ParseNetstatOutputForPort(input)).To(Equal([]scanner.NetstatPort{
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
})
