package tlsscan_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/paraphernalia/test/certtest"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/tlsscan"
)

var _ = Describe("TLS Scan", func() {
	var (
		server *httptest.Server
		logger scanlog.Logger
	)

	BeforeEach(func() {
		// crypto/tls uses the stdlib log package
		log.SetOutput(GinkgoWriter)

		logger = scanlog.NewNopLogger()
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

			result, err := tlsscan.Scan(logger, host, port)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.HasTLS()).To(BeTrue())

			Expect(result).To(HaveKeyWithValue("VersionTLS10", []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}))
			Expect(result).To(HaveKeyWithValue("VersionTLS11", []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}))
			Expect(result).To(HaveKeyWithValue("VersionTLS12", []string{}))
		})
	})

	Context("scanning a server that does not support TLS", func() {
		BeforeEach(func() {
			server.Start()
		})

		It("performs a scan", func() {
			host, port := hostport(server.URL)
			result, err := tlsscan.Scan(logger, host, port)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.HasTLS()).To(BeFalse())

			Expect(result).To(HaveKeyWithValue("VersionTLS10", []string{}))
			Expect(result).To(HaveKeyWithValue("VersionTLS11", []string{}))
			Expect(result).To(HaveKeyWithValue("VersionTLS12", []string{}))
		})
	})

	Context("scanning a server that supports mutual TLS", func() {
		var (
			listener net.Listener
		)

		BeforeEach(func() {
			ca, err := certtest.BuildCA("tlsscan")
			Expect(err).NotTo(HaveOccurred())

			pool, err := ca.CertPool()
			Expect(err).NotTo(HaveOccurred())

			cert, err := ca.BuildSignedCertificate("server")
			Expect(err).NotTo(HaveOccurred())

			tlsCert, err := cert.TLSCertificate()
			Expect(err).NotTo(HaveOccurred())

			config := &tls.Config{
				MinVersion:               tls.VersionTLS12,
				ClientAuth:               tls.RequireAndVerifyClientCert,
				ClientCAs:                pool,
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
				CurvePreferences: []tls.CurveID{
					tls.CurveP384,
				},
				Certificates: []tls.Certificate{tlsCert},
			}

			// Curiously, the mutual TLS configuration above does not play well with
			// the httptest.Server. Creating the listener ourselves works.
			listener, err = tls.Listen("tcp", "127.0.0.1:0", config)
			Expect(err).NotTo(HaveOccurred())

			go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "hello?")
			}))
		})

		AfterEach(func() {
			listener.Close()
		})

		It("performs a scan", func() {
			host, port, err := net.SplitHostPort(listener.Addr().String())
			Expect(err).NotTo(HaveOccurred())

			result, err := tlsscan.Scan(logger, host, port)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.HasTLS()).To(BeTrue())

			Expect(result).To(HaveKeyWithValue("VersionTLS10", []string{}))
			Expect(result).To(HaveKeyWithValue("VersionTLS11", []string{}))
			Expect(result).To(HaveKeyWithValue("VersionTLS12", []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			}))
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
