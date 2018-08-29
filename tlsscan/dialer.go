package tlsscan

import (
	"crypto/tls"
	"github.com/pivotal-cf/scantron/scanlog"
	"net"
	"reflect"
	"strings"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: AttemptHandshake timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var emptyConfig tls.Config

func defaultConfig() *tls.Config {
	return &emptyConfig
}

// copied from crypto/tls/DialWithDialer, modified to immediately close the connection
// return nil if cipher was negotiated successfully, even if the handshake failed in a later step (e.g. client cert validation)
func AttemptHandshake(logger scanlog.Logger, dialer *net.Dialer, network, addr string, config *tls.Config) (error) {

	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(dialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := tls.Client(rawConn, config)

	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	// use reflection to check connection's ciphersuite (ConnectionStatus isn't set if handshake fails)

	rConn := reflect.ValueOf(conn).Elem()
	cipherSuite := rConn.FieldByName("cipherSuite")
	clientProtocol := rConn.FieldByName("clientProtocol")
	clientProtocolFallback := rConn.FieldByName("clientProtocolFallback")
	vers := rConn.FieldByName("vers")

	logger.Debugf("Connection State After Handshake: %d '%s' %s %d", cipherSuite, clientProtocol, clientProtocolFallback, vers)

	if err != nil {
		rawConn.Close()
	} else {
		conn.Close()
	}

	if cipherSuite.Uint() == 0 {
		return err
	}

	return nil
}