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

			for _, service := range nmapResult {
				for _, port := range result.Ports {
					if port.Number != service.Port {
						continue
					}

					if service.SSL {
						results[i].TLSInformation.Presence = true

						hostport := net.JoinHostPort(result.IP, strconv.Itoa(port.Number))
						cert, err := FetchTLSInformation(hostport)
						if err == nil {
							results[i].TLSInformation.Certificate = cert
						}

						results[i].TLSInformation.CipherInformation = service.CipherInformation
					}
				}
			}
		}

		return results, nil
	})
}
