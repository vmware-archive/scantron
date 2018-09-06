package tlsscan

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/pivotal-cf/scantron"
)

var ErrExpectedAbort = errors.New("tls: aborting handshake")

func (s *TlsScannerImpl) FetchTLSInformation(host, port string) (*scantron.Certificate, bool, error) {
	certs := []x509.Certificate{}
	mutual := false

	config := &tls.Config{
		// We never send secret information over this TLS connection. We're just
		// probing it.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}

				certs = append(certs, *cert)
			}

			return nil
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			mutual = true
			return nil, ErrExpectedAbort
		},
	}

	hostport := net.JoinHostPort(host, port)
	conn, err := tls.Dial("tcp", hostport, config)
	if err != nil && err != ErrExpectedAbort {
		return nil, false, err
	}

	if conn != nil {
		_ = conn.Close()
	}

	// XXX: We only get the first certificate given to us.
	cert := certs[0]
	var bits int

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits = key.N.BitLen()
	case *ecdsa.PublicKey:
		bits = key.Params().BitSize
	default:
		msg := fmt.Sprintf("did not know how to convert type: %T", key)
		panic(msg)
	}

	certificate := &scantron.Certificate{
		Bits:       bits,
		Expiration: cert.NotAfter,
		Subject: scantron.CertificateSubject{
			Country:  singleton(cert.Subject.Country),
			Province: singleton(cert.Subject.Province),
			Locality: singleton(cert.Subject.Locality),

			Organization: singleton(cert.Subject.Organization),
			CommonName:   cert.Subject.CommonName,
		},
	}

	return certificate, mutual, nil
}

func singleton(array []string) string {
	if len(array) > 0 {
		return array[0]
	}

	return ""
}
