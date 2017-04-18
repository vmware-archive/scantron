package tls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	conn     net.Conn
	isClient bool

	// constant after handshake; protected by handshakeMutex
	handshakeMutex sync.Mutex // handshakeMutex < in.Mutex, out.Mutex, errMutex
	// handshakeCond, if not nil, indicates that a goroutine is committed
	// to running the handshake for this Conn. Other goroutines that need
	// to wait for the handshake can wait on this, under handshakeMutex.
	handshakeCond *sync.Cond
	handshakeErr  error   // error resulting from handshake
	vers          uint16  // TLS version
	haveVers      bool    // version has been negotiated
	config        *Config // configuration passed to constructor
	// handshakeComplete is true if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	handshakeComplete bool
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes int

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// input/output
	in, out   halfConn     // in.Mutex < out.Mutex
	rawInput  *block       // raw input, right off the wire
	input     *block       // application data waiting to be read
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent counts the bytes of application data sent.
	// packetsSent counts packets.
	bytesSent   int64
	packetsSent int64

	// activeCall is an atomic int32; the low bit is whether Close has
	// been called. the rest of the bits are the number of goroutines
	// in Conn.Write.
	activeCall int32

	tmp [16]byte
}

func (c *Conn) handleRenegotiation() error {
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	_, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return alertUnexpectedMessage
	}

	return c.sendAlert(alertNoRenegotiation)
}

func (c *Conn) serverHandshake() error {
	return nil
}

func (c *Conn) clientHandshake() error {
	hello := &clientHelloMsg{
		vers:                         c.config.Version,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(c.config.ServerName),
		supportedCurves:              defaultCurvePreferences,
		supportedPoints:              []uint8{pointFormatUncompressed},
		nextProtoNeg:                 false,
		secureRenegotiationSupported: true,
		alpnProtocols:                []string{},
		cipherSuites:                 []uint16{c.config.CipherSuite},
	}

	_, err := io.ReadFull(rand.Reader, hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.signatureAndHashes = supportedSignatureAlgorithms
	}

	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", serverHello.vers)
	}
	c.vers = vers
	c.haveVers = true

	suiteFound := mutualCipherSuite(hello.cipherSuites, serverHello.cipherSuite)
	if !suiteFound {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	c.handshakeComplete = true

	return nil
}
