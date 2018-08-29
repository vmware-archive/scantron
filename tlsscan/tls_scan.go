package tlsscan

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"crypto/tls"
	"strings"

	"time"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"golang.org/x/sync/semaphore"
)

const (
	maxInFlight = 20
)

type result struct {
	version string
	suite   string
}

func release(logger scanlog.Logger, sem *semaphore.Weighted, wg *sync.WaitGroup) {
	logger.Debugf("Releasing locks")
	sem.Release(1)
	wg.Done()
}

func Scan(logger scanlog.Logger, host string, port string) (scantron.CipherInformation, error) {
	results := scantron.CipherInformation{}
	for _, version := range ProtocolVersions {
		results[version.Name] = []string{}
	}

	logger.Infof("About to test %s:%s", host, port)
	supportedProtocols := getSupportedProtocols(logger, host, port)
	if len(supportedProtocols) == 0 {
		logger.Infof("Skipping cipher scan for %s:%s (no supported protocols)", host, port)
		return results, nil
	}

	logger.Infof("Starting cipher scan for %s:%s", host, port)

	sem := semaphore.NewWeighted(maxInFlight)
	ciphersuites:= len(supportedProtocols) * len(CipherSuites)
	resultChan := make(chan result, maxInFlight)

	wg := &sync.WaitGroup{}
	wg.Add(ciphersuites)

	go func(logger scanlog.Logger) {
		for _, version := range supportedProtocols {
			logger.Debugf("Starting TLS version %s", version.Name)
			for _, cipherSuite := range CipherSuites {
				logger.Debugf("Starting ciphersuite %s", cipherSuite.Name)
				scanLogger := logger.With(
					"host", host,
					"port", port,
					"version", version.Name,
					"suite", cipherSuite.Name,
				)

				if err := sem.Acquire(context.Background(), 1); err != nil {
					scanLogger.Errorf("Failed to acquire lock: %q", err)
				}
				scanLogger.Debugf("Acquired lock")

				go testCipher(scanLogger, version, cipherSuite, sem, wg, host, port, resultChan)
			}
			logger.Debugf("Finished TLS version %s", version.Name)
		}
	} (logger)

	go func(logger scanlog.Logger) {
		wg.Wait()
		logger.Debugf("Wait group done")
		close(resultChan)
	}(logger)

	logger.Debugf("About to start reading from channel")
	for res := range resultChan {
		logger.Debugf("Read %s %s from channel", res.version, res.suite)
		results[res.version] = append(results[res.version], res.suite)
	}

	logger.Infof("Finished cipher scan for %s:%s", host, port)
	return results, nil
}

func testCipher(
	logger scanlog.Logger,
	version ProtocolVersion,
	cipherSuite CipherSuite,
	sem *semaphore.Weighted,
	wg *sync.WaitGroup,
	host string,
	port string,
	resultChan chan result) {
	defer release(logger, sem, wg)
	found, err := tryHandshakeWithCipher(logger, host, port, version, cipherSuite)
	if err != nil {
		logger.Debugf("Remote server did not respond affirmatively to request: %s", err)
		return
	}

	if found {
		logger.Debugf("Sending result")
		resultChan <- result{
			version: version.Name,
			suite:   cipherSuite.Name,
		}
		logger.Debugf("Result sent")
	}
	logger.Debugf("Finished ciphersuite %s", cipherSuite.Name)
}


func getSupportedProtocols(logger scanlog.Logger, host string, port string) ([]ProtocolVersion) {
	supportedVersions := []ProtocolVersion{}
	for _, version := range ProtocolVersions {
		providesCert := false
		wantsCert := false
		config := tls.Config{
			MinVersion:version.ID,
			MaxVersion:version.ID,
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				providesCert = true
				return nil
			},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				wantsCert = true
				return nil, ErrExpectedAbort
			},
		}
		err := AttemptHandshake(logger, &net.Dialer{Timeout: 1 * time.Second}, "tcp", fmt.Sprintf("%s:%s", host, port), &config)
		logger.Infof("%s:%s provides cert %b wants cert %b (%s)", host, port, providesCert, wantsCert, err)

		if providesCert {
			logger.Infof("%s:%s accepts TLS (%s)", host, port, version.Name)
			supportedVersions = append(supportedVersions, version)
		} else {
			logger.Infof("%s:%s refuses TLS (%s %s)", host, port, version.Name, err)
		}
	}
	return supportedVersions
}

func tryHandshakeWithCipher(logger scanlog.Logger, host string, port string, version ProtocolVersion, cipherSuite CipherSuite) (bool, error) {
	config := tls.Config{
		MinVersion:     version.ID,
		MaxVersion:     version.ID,
		CipherSuites: []uint16{cipherSuite.ID},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: nil,
	}

	address := fmt.Sprintf("%s:%s", host, port)
	logger.Debugf("Dialing %s %s %s", address, version.Name, cipherSuite.Name)
	err := AttemptHandshake(logger, &net.Dialer{Timeout: 10*time.Second}, "tcp", address, &config)

	if err != nil {
		if strings.Contains(err.Error(), "remote error") {
			logger.Debugf("Dialed: no tls for %s %s %s (%s)", address, version.Name, cipherSuite.Name, err)
			return false, nil
		}

		// TODO are these meant to be recorded in tls_scan_errors?
		logger.Debugf("Dialed: error for %s %s %s: %s", address, version.Name, cipherSuite.Name, err)
		return false, err
	}

	logger.Debugf("Dialed: tls available for %s %s %s", address, version.Name, cipherSuite.Name)
	return true, nil
}



