package tls

import (
	"context"
	"net"
	"strings"
	"time"
	"github.com/pivotal-cf/scantron/scanlog"
)

func Dial(logger scanlog.Logger, ctx context.Context, network, addr string, config *Config) error {
	dialer := net.Dialer{
		Timeout: 1*time.Second,
	}
	logger.Debugf("About to DialContext")
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
	logger.Debugf("Error with DialContext")
		return err
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(1*time.Second))

	// This can be sent in rapid succession and will quickly exhaust machine
	// resources due to the number of sockets being left in the TIME_WAIT state.
	// To avoid this we tell the connection not to linger waiting for any
	// remaining data.
	logger.Debugf("About to wrap TCP connection")
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		logger.Debugf("About to configure TCP connection")
		tcpConn.SetLinger(0)
		tcpConn.SetDeadline(time.Now().Add(1*time.Second))
		defer tcpConn.Close()
	}

	if config.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]

		config.ServerName = hostname
	}

	logger.Debugf("About to wrap client connection")
	conn := Client(rawConn, config)

	errs := make(chan error, 1)
	go func() {

		logger.Debugf("About to handshake")
		errs <- conn.Handshake()
	}()

	select {
	case err := <-errs:
		logger.Debugf("Handshake error")
		return err
	case <-ctx.Done():
		logger.Debugf("Handshake success")
		conn.Close()
		return ctx.Err()
	}
}
