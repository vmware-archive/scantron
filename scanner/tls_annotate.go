package scanner

import (
	"net"
	"strconv"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
)

type scannerFunc func(logger lager.Logger) ([]ScannedService, error)

func (s scannerFunc) Scan(logger lager.Logger) ([]ScannedService, error) {
	return s(logger)
}

func AnnotateWithTLSInformation(scanner Scanner, nmapResults scantron.NmapResults) Scanner {
	return scannerFunc(func(logger lager.Logger) ([]ScannedService, error) {
		results, err := scanner.Scan(logger)
		if err != nil {
			return nil, err
		}

		for i, result := range results {
			nmapResult := nmapResults[result.IP]

			if result.SSL {
				hostport := net.JoinHostPort(result.IP, strconv.Itoa(result.Port))
				cert, err := FetchTLSInformation(hostport)
				if err != nil {
					continue
				}

				result.TLSCert = cert

				for _, service := range nmapResult {
					if result.Port == service.Port {
						result.SSLInformation = service.SSLInformation
						break
					}
				}

				results[i] = result
			}
		}

		return results, nil
	})
}
