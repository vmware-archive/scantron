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
	defer rawConn.Close()

	// This can be sent in rapid succession and will quickly exhaust machine
	// resources due to the number of sockets being left in the TIME_WAIT state.
	// To avoid this we tell the connection not to linger waiting for any
	// remaining data.
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetLinger(0)
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
			return err
		}

		return conn.Close()
	case <-ctx.Done():
		return ctx.Err()
	}
}
