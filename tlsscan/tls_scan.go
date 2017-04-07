package tlsscan

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

var (
	tlsVersions = []string{
		"tls1.0",
		"tls1.1",
		"tls1.2",
	}

	ciphersuites []string
)

const (
	maxInFlight    = 20
	opensslTimeout = 3 * time.Second
)

func init() {
	bs, err := exec.Command("openssl", "ciphers").Output()
	if err != nil {
		panic("openssl command not on path!")
	}

	ciphersuites = strings.Split(strings.TrimSpace(string(bs)), ":")
}

type result struct {
	version string
	suite   string
}

func Scan(host string, port string) (Results, error) {
	results := Results{}

	for _, version := range tlsVersions {
		results[version] = []string{}
	}

	sem := semaphore.NewWeighted(maxInFlight)
	resultChan := make(chan result)

	wg := &sync.WaitGroup{}
	wg.Add(len(tlsVersions) * len(ciphersuites))

	for _, version := range tlsVersions {
		for _, suite := range ciphersuites {
			go func(version, suite string) {
				defer wg.Done()

				if err := sem.Acquire(context.Background(), 1); err != nil {
					log.Println(err)
					return
				}
				defer sem.Release(1)

				found, err := scan(host, port, version, suite)
				if err != nil {
					log.Printf("could not scan (%s, %s): %s\n", version, suite, err)
					return
				}

				if found {
					resultChan <- result{
						version: version,
						suite:   suite,
					}
				}
			}(version, suite)
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

func scan(host, port, version, suite string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opensslTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "openssl", "s_client",
		"-connect", fmt.Sprintf("%s:%s", host, port),
		"-cipher", suite,
		opensslArg[version],
	)

	bs, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(bs, []byte(":error:")) || bytes.Contains(bs, []byte("errno=54")) {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
}

var opensslArg = map[string]string{
	"ssl3.0": "-ssl3",
	"tls1.0": "-tls1",
	"tls1.1": "-tls1_1",
	"tls1.2": "-tls1_2",
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
