package scanner_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("TLS", func() {
	Describe("Certificate Report", func() {
		var server *httptest.Server

		BeforeEach(func() {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, client")
			})

			server = httptest.NewTLSServer(handler)
		})

		AfterEach(func() {
			server.Close()
		})

		It("should show TLS certificate details", func() {
			url, err := url.Parse(server.URL)
			Expect(err).NotTo(HaveOccurred())

			cert, err := scanner.FetchTLSInformation(url.Host)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cert).ShouldNot(BeNil())

			Expect(cert.Bits).To(Equal(1024))

			expectedExpiration := time.Date(2084, time.January, 29, 16, 0, 0, 0, time.UTC)
			Expect(cert.Expiration).To(BeTemporally("==", expectedExpiration))
			Expect(cert.Subject.Country).To(Equal(""))
			Expect(cert.Subject.Province).To(Equal(""))
			Expect(cert.Subject.Locality).To(Equal(""))
			Expect(cert.Subject.Organization).To(Equal("Acme Co"))
			Expect(cert.Subject.CommonName).To(Equal(""))
		})
	})

	Describe("Certificate Subject", func() {
		It("displays in a familiar format", func() {
			subject := scanner.CertificateSubject{
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
