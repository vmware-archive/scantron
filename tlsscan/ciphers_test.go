package tlsscan_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/tlsscan"
)

var _ = Describe("Ciphers", func() {
	Context("parsing IANA TLS parameters CSV", func() {
		BeforeEach(func() {

		})

		It("returns a list of ciphers", func() {
			ciphers, err := tlsscan.BuildCipherSuites()

			Expect(err).NotTo(HaveOccurred())
			Expect(ciphers).To(HaveLen(339), "have elements")
			Expect(ciphers).To(ContainElement(tlsscan.CipherSuite{
				ID:          0x009E,
				Name:        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
				DTls:        true,
				Recommended: true,
			}))
		})
	})
})
