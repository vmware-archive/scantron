package scanner

import (
	"net"
	"strconv"

	"github.com/pivotal-golang/lager"
)

type scannerFunc func(logger lager.Logger) ([]ScannedService, error)

func (s scannerFunc) Scan(logger lager.Logger) ([]ScannedService, error) {
	return s(logger)
}

func AnnotateWithTLSInformation(scanner Scanner) Scanner {
	return scannerFunc(func(logger lager.Logger) ([]ScannedService, error) {
		results, err := scanner.Scan(logger)
		if err != nil {
			return nil, err
		}

		for i, result := range results {
			if result.SSL {
				hostport := net.JoinHostPort(result.IP, strconv.Itoa(result.Port))
				cert, err := FetchTLSInformation(hostport)
				if err != nil {
					continue
				}

				result.TLSCert = cert
				results[i] = result
			}
		}

		return results, nil
	})
}
