package tls

import (
	"context"
	"net"
	"strings"
)

func Dial(ctx context.Context, network, addr string, config *Config) error {
	dialer := net.Dialer{}

	rawConn, err := dialer.DialContext(ctx, network, addr)
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
