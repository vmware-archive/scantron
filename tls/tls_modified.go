package tls

import (
	"net"
	"strings"
)

func Dial(network, addr string, config *Config) error {
	dialer := net.Dialer{}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return err
	}

	if config.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]

		config.ServerName = hostname
	}

	conn := Client(rawConn, config)

	err = conn.Handshake()
	if err != nil {
		rawConn.Close()
		return err
	}

	err = conn.Close()
	if err != nil {
		return err
	}
	return nil
}
