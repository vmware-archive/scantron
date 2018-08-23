package tlsscan

import (
	"context"
	"fmt"
	"sync"

	"strings"

	"time"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/tls"
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

	logger.Infof("Starting port scan for %s:%s", host, port)

	for _, version := range tls.ProtocolVersions {
		results[version.Name] = []string{}
	}

	sem := semaphore.NewWeighted(maxInFlight)
	ciphersuites:=(len(tls.ProtocolVersions) * len(tls.CipherSuites))
	resultChan := make(chan result, maxInFlight)

	wg := &sync.WaitGroup{}
	wg.Add(ciphersuites)

	go func(logger scanlog.Logger) {
		for _, version := range tls.ProtocolVersions {
			logger.Debugf("Starting TLS version %s", version.Name)
			for _, cipherSuite := range tls.CipherSuites {
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

				go func(logger scanlog.Logger, version tls.ProtocolVersion, cipherSuite tls.CipherSuite) {
					defer release(logger, sem, wg)
					found, err := scan(logger, host, port, version, cipherSuite)
					if err != nil {
						logger.Debugf("Remote server did not respond affirmitavely to request: %s", err)
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
				}(scanLogger, version, cipherSuite)
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

	logger.Infof("Finished scan for %s:%s", host, port)
	return results, nil
}

func scan(logger scanlog.Logger, host string, port string, version tls.ProtocolVersion, cipherSuite tls.CipherSuite) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := tls.Config{
		Version:     version.ID,
		CipherSuite: cipherSuite.ID,
	}

	address := fmt.Sprintf("%s:%s", host, port)
	logger.Debugf("Dialing %s %s %s", address, version.Name, cipherSuite.Name)
	err := tls.Dial(logger, ctx, "tcp", address, &config)
	if err != nil {
		if strings.HasPrefix(err.Error(), "tls: remote error") {
			logger.Debugf("Dialed: no tls for %s %s %s", address, version.Name, cipherSuite.Name)
			return false, nil
		}

		logger.Debugf("Dialed: error for %s %s %s:%s", address, version.Name, cipherSuite.Name, err)
		return false, err
	}

	logger.Debugf("Dialed: tls available for %s %s %s", address, version.Name, cipherSuite.Name)
	return true, nil
}
