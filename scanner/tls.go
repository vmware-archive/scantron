package scanner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"

	"github.com/pivotal-cf/scantron"
)

func FetchTLSInformation(hostport string) (*scantron.Certificate, error) {
	config := &tls.Config{
		// We never send secret information over this TLS connection. We're just
		// probing it.
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", hostport, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

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

	return certificate, nil
}

func singleton(array []string) string {
	if len(array) > 0 {
		return array[0]
	}

	return ""
}
