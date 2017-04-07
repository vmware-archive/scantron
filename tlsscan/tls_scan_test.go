package tlsscan_test

import (
	"net"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pivotal-cf/scantron/tlsscan"
)

var _ = Describe("TLS Scan", func() {
	var server *httptest.Server

	BeforeEach(func() {
		log.SetOutput(GinkgoWriter)

		server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "hello?")
		}))
	})

	AfterEach(func() {
		server.Close()
	})

	Context("scanning a server that supports TLS", func() {
		BeforeEach(func() {
			config := &tls.Config{
				MinVersion: tls.VersionTLS10,
				MaxVersion: tls.VersionTLS11, // no tls 1.2
				CipherSuites: []uint16{
					// Note: this is an old cipher that should not be used but
					// it it widely supported and therefore useful for this test.
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				},
			}

			server.TLS = config
			server.StartTLS()
		})

		It("performs a scan", func() {
			host, port := hostport(server.URL)

			result, err := tlsscan.Scan(host, port)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.HasTLS()).To(BeTrue())

			Expect(result).To(HaveKeyWithValue("tls1.0", []string{"AES128-SHA"}))
			Expect(result).To(HaveKeyWithValue("tls1.1", []string{"AES128-SHA"}))
			Expect(result).To(HaveKeyWithValue("tls1.2", []string{}))
		})
	})

	Context("scanning a server that does not support TLS", func() {
		BeforeEach(func() {
			server.Start()
		})

		It("performs a scan", func() {
			host, port := hostport(server.URL)
			result, err := tlsscan.Scan(host, port)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.HasTLS()).To(BeFalse())

			Expect(result).To(HaveKeyWithValue("tls1.0", []string{}))
			Expect(result).To(HaveKeyWithValue("tls1.1", []string{}))
			Expect(result).To(HaveKeyWithValue("tls1.2", []string{}))
		})
	})
})

func hostport(uri string) (string, string) {
	pu, err := url.Parse(uri)
	Expect(err).ShouldNot(HaveOccurred())

	host, port, err := net.SplitHostPort(pu.Host)
	Expect(err).ShouldNot(HaveOccurred())

	return host, port
}
