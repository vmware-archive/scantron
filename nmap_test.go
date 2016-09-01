package scantron_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron"

	nmap "github.com/lair-framework/go-nmap"
)

var _ = Describe("Nmap", func() {
	Describe("converting an nmap.Run into a scantron.NmapResults", func() {
		var results scantron.NmapResults

		BeforeEach(func() {
			run := &nmap.NmapRun{
				Hosts: []nmap.Host{
					{
						Hostnames: []nmap.Hostname{
							{Name: "host1"},
						},
						Addresses: []nmap.Address{
							{Addr: "10.0.0.1"},
							{Addr: "10.0.0.2"},
						},
						Ports: []nmap.Port{
							{
								PortId: 1234,
								Service: nmap.Service{
									Tunnel: "ssl",
								},
							},
							{
								PortId: 9252,
							},
						},
					},
					{
						Addresses: []nmap.Address{
							{Addr: "10.0.0.3"},
						},
						Ports: []nmap.Port{
							{
								PortId: 9375,
							},
						},
					},
				},
			}
			results = scantron.BuildNmapResults(run)
		})

		It("provides map access to the nmap results", func() {
			firstResult, found := results["10.0.0.1"]
			Expect(found).To(BeTrue())
			Expect(firstResult).To(ConsistOf(
				scantron.Service{
					Port: 1234,
					SSL:  true,
				},
				scantron.Service{
					Port: 9252,
					SSL:  false,
				},
			))

			secondResult, found := results["10.0.0.3"]
			Expect(found).To(BeTrue())
			Expect(secondResult).To(ConsistOf(
				scantron.Service{
					Port: 9375,
					SSL:  false,
				},
			))
		})

		It("returns false if there is no such host", func() {
			_, found := results["10.0.0.100"]
			Expect(found).To(BeFalse())
		})

		It("lets results be looked up by hostname", func() {
			result, found := results["host1"]
			Expect(found).To(BeTrue())
			Expect(result).To(ConsistOf(
				scantron.Service{
					Port: 1234,
					SSL:  true,
				},
				scantron.Service{
					Port: 9252,
					SSL:  false,
				},
			))
		})
	})

	Describe("converting an nmap.Run into a scantron.NmapResults", func() {
		var input string

		BeforeEach(func() {
			input = `
   TLSv1.0: 
     ciphers:
       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
     compressors:
       NULL
     cipher preference: indeterminate
     cipher preference error: Too few ciphers supported
     warnings:
       Weak certificate signature: SHA1
   TLSv1.1: 
     ciphers:
       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
     compressors:
       NULL
     cipher preference: indeterminate
     cipher preference error: Too few ciphers supported
     warnings:
       Weak certificate signature: SHA1
   TLSv1.2: 
     ciphers:
       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
       TLS_RSA_WITH_AES_128_CBC_SHA256 (rsa 2048) - A
       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
     compressors:
       NULL
     cipher preference: server
     warnings:
       Weak certificate signature: SHA1
   least strength: A`

		})

		It("builds SSL information from Nmap script output", func() {
			output := scantron.ExtractSSLInformation(input)
			Expect(output).To(Equal(scantron.CipherInformation{
				"TLSv1.0": []scantron.SSLCipher{
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Quality: "A"},
				},
				"TLSv1.1": []scantron.SSLCipher{
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Quality: "A"},
				},
				"TLSv1.2": []scantron.SSLCipher{
					{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Quality: "A"},
					{Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Quality: "A"},
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA256", Quality: "A"},
					{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Quality: "A"},
				},
			}))
		})

		It("returns an empty map if the input is empty", func() {
			output := scantron.ExtractSSLInformation("")
			Expect(output).To(BeEmpty())
		})
	})
})
