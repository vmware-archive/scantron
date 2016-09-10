package scanner

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"time"
)

type Certificate struct {
	Expiration time.Time
	Bits       int
	Subject    CertificateSubject
}

type CertificateSubject struct {
	Country  string
	Province string
	Locality string

	Organization string
	CommonName   string
}

func (cs CertificateSubject) String() string {
	return fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/CN=%s", cs.Country, cs.Province, cs.Locality, cs.Organization, cs.CommonName)
}

func FetchTLSInformation(hostport string) (*Certificate, error) {
	config := &tls.Config{
		// We never send secret information over this TLS connection. We're just
		// probing it.
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", hostport, config)
	if err != nil {
		fmt.Println("err:", err.Error())
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

	certificate := &Certificate{
		Bits:       bits,
		Expiration: cert.NotAfter,
		Subject: CertificateSubject{
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
