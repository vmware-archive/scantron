package tls

import (
	"crypto/rand"
	"io"
)

type Config struct {
	Version     uint16
	CipherSuite uint16
	ServerName  string
}

func (c *Config) rand() io.Reader {
	return rand.Reader
}

func (c *Config) mutualVersion(vers uint16) (uint16, bool) {
	if vers == c.Version {
		return vers, true
	}

	return 0, false
}
