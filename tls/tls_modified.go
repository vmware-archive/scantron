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

	errs := make(chan error, 1)
	go func() {
		errs <- conn.Handshake()
	}()

	select {
	case err := <-errs:
		if err != nil {
			rawConn.Close()
			return err
		}

		return conn.Close()
	case <-ctx.Done():
		rawConn.Close()
		return ctx.Err()
	}
}
