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

func Scan(logger scanlog.Logger, host string, port string) (scantron.CipherInformation, error) {
	results := scantron.CipherInformation{}

	logger.Infof("Starting ciphersuite scan")
	defer logger.Infof("Ciphersuite scan complete")

	for _, version := range tls.ProtocolVersions {
		results[version.Name] = []string{}
	}

	sem := semaphore.NewWeighted(maxInFlight)
	resultChan := make(chan result)

	wg := &sync.WaitGroup{}
	wg.Add(len(tls.ProtocolVersions) * len(tls.CipherSuites))

	for _, version := range tls.ProtocolVersions {
		for _, cipherSuite := range tls.CipherSuites {
			scanLogger := logger.With(
				"host", host,
				"port", port,
				"version", version.Name,
				"suite", cipherSuite.Name,
			)

			if err := sem.Acquire(context.Background(), 1); err != nil {
				scanLogger.Errorf("Failed to acquire lock: %q", err)
			}

			go func(logger scanlog.Logger, version tls.ProtocolVersion, cipherSuite tls.CipherSuite) {
				defer sem.Release(1)
				defer wg.Done()

				found, err := scan(host, port, version, cipherSuite)
				if err != nil {
					logger.Debugf("Remote server did not respond affirmitavely to request: %s", err)
					return
				}

				if found {
					resultChan <- result{
						version: version.Name,
						suite:   cipherSuite.Name,
					}
				}
			}(scanLogger, version, cipherSuite)
		}
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for res := range resultChan {
		results[res.version] = append(results[res.version], res.suite)
	}

	return results, nil
}

func scan(host, port string, version tls.ProtocolVersion, cipherSuite tls.CipherSuite) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := tls.Config{
		Version:     version.ID,
		CipherSuite: cipherSuite.ID,
	}

	address := fmt.Sprintf("%s:%s", host, port)
	if err := tls.Dial(ctx, "tcp", address, &config); err != nil {
		if strings.HasPrefix(err.Error(), "tls: remote error") {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
