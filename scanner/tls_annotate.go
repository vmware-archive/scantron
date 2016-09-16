package scanner

import (
	"net"
	"strconv"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
)

type scannerFunc func(logger lager.Logger) ([]ScannedHost, error)

func (s scannerFunc) Scan(logger lager.Logger) ([]ScannedHost, error) {
	return s(logger)
}

func AnnotateWithTLSInformation(scanner Scanner, nmapResults scantron.NmapResults) Scanner {
	return scannerFunc(func(logger lager.Logger) ([]ScannedHost, error) {
		scannedHosts, err := scanner.Scan(logger)
		if err != nil {
			return nil, err
		}

		for j, scannedHost := range scannedHosts {

			services := scannedHost.Services

			for _, hostService := range services {
				nmapResult := nmapResults[scannedHost.IP]

				for _, nmapService := range nmapResult {
					ports := hostService.Ports

					for n, port := range ports {
						if port.Number != nmapService.Port {
							continue
						}

						if port.State != "LISTEN" {
							continue
						}

						if nmapService.SSL {
							port := ports[n]
							port.TLSInformation.Presence = true

							hostport := net.JoinHostPort(scannedHost.IP, strconv.Itoa(port.Number))
							cert, err := FetchTLSInformation(hostport)
							if err != nil {
								port.TLSInformation.ScanError = err
							} else {
								port.TLSInformation.Certificate = cert
							}

							port.TLSInformation.CipherInformation = nmapService.CipherInformation
							ports[n] = port
						}
					}
				}
			}

			scannedHosts[j].Services = services
		}

		return scannedHosts, nil
	})
}
