package main_test

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var _ = Describe("ssh-keyscan", func() {
	Context("with an SSH server", func() {
		var listener net.Listener

		BeforeEach(func() {
			var err error

			listener, err = net.Listen("tcp", "127.0.0.1:0") //:0 is random port
			Expect(err).NotTo(HaveOccurred())

			startSshServer(listener)
		})

		AfterEach(func() {
			listener.Close()
		})

		It("prints the key type for rsa keys", func() {
			address := listener.Addr().String()

			session := runCommand("ssh-keyscan", address)
			Eventually(session).Should(gexec.Exit(0))

			Expect(session.Out).To(gbytes.Say("%s ssh-rsa AAAA", address))
			Expect(session.Out).To(gbytes.Say("%s ssh-dss AAAA", address))
			Expect(session.Out).To(gbytes.Say("%s ecdsa-sha2-nistp256 AAAA", address))
			Expect(session.Out).To(gbytes.Say("%s ecdsa-sha2-nistp384 AAAA", address))
			Expect(session.Out).To(gbytes.Say("%s ecdsa-sha2-nistp521 AAAA", address))
			Expect(session.Out).To(gbytes.Say("%s ssh-ed25519 AAAA", address))
		})
	})

	It("defaults to port 22 and prints an error when there's a connection failure", func() {
		session := runCommand("ssh-keyscan", "999.999.999.999")
		Eventually(session).Should(gexec.Exit(1))

		Expect(session.Err).To(gbytes.Say("error"))
		Expect(session.Err).To(gbytes.Say("no such host"))
	})
})

func startSshServer(listener net.Listener) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, errors.New("You shall not pass")
		},
	}

	addKey(config, generateRsaKey())
	addKey(config, generateDsaKey())
	addKey(config, generateEcdsaKey(elliptic.P256()))
	addKey(config, generateEcdsaKey(elliptic.P384()))
	addKey(config, generateEcdsaKey(elliptic.P521()))
	addKey(config, generateEd25519Key())

	go func() {
		defer GinkgoRecover()

		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			ssh.NewServerConn(conn, config)
		}
	}()
}

func addKey(config *ssh.ServerConfig, key interface{}) {
	signer, err := ssh.NewSignerFromKey(key)
	Expect(err).NotTo(HaveOccurred())

	config.AddHostKey(signer)
}

func generateRsaKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	Expect(err).NotTo(HaveOccurred())

	return key
}

func generateDsaKey() *dsa.PrivateKey {
	key := &dsa.PrivateKey{}

	dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160)

	err := dsa.GenerateKey(key, rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	return key
}

func generateEcdsaKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return key
}

func generateEd25519Key() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return key
}
