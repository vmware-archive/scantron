package tlsscan

import (
	"context"
	"fmt"
	"sync"

	"strings"

	"time"

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

func Scan(logger scanlog.Logger, host string, port string) (Results, error) {
	results := Results{}

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
			go func(version tls.ProtocolVersion, cipherSuite tls.CipherSuite) {
				defer wg.Done()

				scanLogger := logger.With(
					"host", host,
					"port", port,
					"version", version.Name,
					"suite", cipherSuite.Name,
				)

				if err := sem.Acquire(context.Background(), 1); err != nil {
					scanLogger.Errorf("Failed to acquire lock:", err)
					return
				}
				defer sem.Release(1)

				found, err := scan(host, port, version, cipherSuite)
				if err != nil {
					scanLogger.Debugf("Remote server did not respond affirmitavely to request: %s", err)
					return
				}

				if found {
					resultChan <- result{
						version: version.Name,
						suite:   cipherSuite.Name,
					}
				}
			}(version, cipherSuite)
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

	address := fmt.Sprintf("%s:%s", host, port)

	config := tls.Config{
		Version:     version.ID,
		CipherSuite: cipherSuite.ID,
	}

	err := tls.Dial(ctx, "tcp", address, &config)
	if err != nil {
		if strings.HasPrefix(err.Error(), "tls: remote error") {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

type Results map[string][]string

func (r Results) HasTLS() bool {
	for _, suites := range r {
		if len(suites) != 0 {
			return true
		}
	}

	return false
}
