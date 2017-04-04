package scanner_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/paraphernalia/secure/tlsconfig"
	"github.com/pivotal-cf/paraphernalia/test/certtest"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("TLS", func() {
	BeforeEach(func() {
		log.SetOutput(GinkgoWriter)
	})

	Describe("Certificate Report", func() {
		var (
			tlsConfig *tls.Config
			server    *httptest.Server
		)

		JustBeforeEach(func() {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			})

			server = httptest.NewUnstartedServer(handler)
			server.TLS = tlsConfig
			server.StartTLS()
		})

		AfterEach(func() {
			server.Close()
		})

		Context("with standard non-mutual TLS", func() {
			BeforeEach(func() {
				ca, err := certtest.BuildCA("scantron")
				Expect(err).NotTo(HaveOccurred())

				cert, err := ca.BuildSignedCertificate("server")
				Expect(err).NotTo(HaveOccurred())

				tlsCert, err := cert.TLSCertificate()
				Expect(err).NotTo(HaveOccurred())

				tlsConfig = tlsconfig.Build(tlsconfig.WithIdentity(tlsCert)).Server()
			})

			It("should show TLS certificate details", func() {
				url, err := url.Parse(server.URL)
				Expect(err).NotTo(HaveOccurred())

				cert, err := scanner.FetchTLSInformation(url.Host)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cert).ShouldNot(BeNil())

				Expect(cert.Bits).To(Equal(1024))

				expectedExpiration := time.Now().Add(365 * 24 * time.Hour)
				Expect(cert.Expiration).To(BeTemporally("~", expectedExpiration, time.Minute))
				Expect(cert.Subject.Country).To(Equal("AQ"))
				Expect(cert.Subject.Province).To(Equal("Ross Island"))
				Expect(cert.Subject.Locality).To(Equal("McMurdo Station"))
				Expect(cert.Subject.Organization).To(Equal("certtest Organization"))
				Expect(cert.Subject.CommonName).To(Equal("server"))
			})
		})

		Context("with mutual TLS", func() {
			BeforeEach(func() {
				ca, err := certtest.BuildCA("scantron")
				Expect(err).NotTo(HaveOccurred())

				pool, err := ca.CertPool()
				Expect(err).NotTo(HaveOccurred())

				cert, err := ca.BuildSignedCertificate("server")
				Expect(err).NotTo(HaveOccurred())

				tlsCert, err := cert.TLSCertificate()
				Expect(err).NotTo(HaveOccurred())

				tlsConfig = tlsconfig.Build(
					tlsconfig.WithIdentity(tlsCert),
				).Server(
					tlsconfig.WithClientAuthentication(pool),
				)
			})

			It("should show TLS certificate details", func() {
				url, err := url.Parse(server.URL)
				Expect(err).NotTo(HaveOccurred())

				cert, err := scanner.FetchTLSInformation(url.Host)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cert).ShouldNot(BeNil())

				Expect(cert.Bits).To(Equal(1024))

				expectedExpiration := time.Now().Add(365 * 24 * time.Hour)
				Expect(cert.Expiration).To(BeTemporally("~", expectedExpiration, time.Minute))
				Expect(cert.Subject.Country).To(Equal("AQ"))
				Expect(cert.Subject.Province).To(Equal("Ross Island"))
				Expect(cert.Subject.Locality).To(Equal("McMurdo Station"))
				Expect(cert.Subject.Organization).To(Equal("certtest Organization"))
				Expect(cert.Subject.CommonName).To(Equal("server"))
			})
		})
	})

	Describe("Certificate Subject", func() {
		It("displays in a familiar format", func() {
			subject := scantron.CertificateSubject{
				Country:  "US",
				Province: "California",
				Locality: "San Francisco",

				Organization: "Pivotal",
				CommonName:   "*.not-real.example.com",
			}

			Expect(subject.String()).To(Equal("/C=US/ST=California/L=San Francisco/O=Pivotal/CN=*.not-real.example.com"))
		})
	})
})
