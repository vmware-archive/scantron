package scantron

import (
	"bufio"
	"regexp"
	"strings"

	nmap "github.com/lair-framework/go-nmap"
)

type Service struct {
	Port              int
	SSL               bool
	CipherInformation CipherInformation
}

type CipherInformation map[string][]SSLCipher

type SSLCipher struct {
	Name    string
	Quality string
}

type NmapResults map[string][]Service

func BuildNmapResults(run *nmap.NmapRun) NmapResults {
	results := NmapResults{}

	for _, host := range run.Hosts {
		services := []Service{}

		for _, port := range host.Ports {
			var sslInfo CipherInformation

			for _, script := range port.Scripts {
				if script.Id != "ssl-enum-ciphers" {
					continue
				}

				sslInfo = ExtractSSLInformation(script.Output)
			}

			services = append(services, Service{
				Port:              port.PortId,
				SSL:               len(port.Service.Tunnel) > 0,
				CipherInformation: sslInfo,
			})
		}

		address := host.Addresses[0].Addr
		results[address] = services

		if len(host.Hostnames) > 0 {
			hostname := host.Hostnames[0].Name
			results[hostname] = services
		}
	}

	return results
}

var tlsRegexp = regexp.MustCompile(`^\s*(TLS_[A-Z0-9_]+) .*- ([A-Z])`)
var tlsVersionRegexp = regexp.MustCompile(`^\s*([A-Z0-9v\.]+):`)

func ExtractSSLInformation(input string) CipherInformation {
	scanner := bufio.NewScanner(strings.NewReader(input))
	ciphers := []SSLCipher{}
	sslInfo := make(map[string][]SSLCipher)

	currentSSLVersion := ""

	for scanner.Scan() {
		line := scanner.Text()

		nameMatches := tlsVersionRegexp.FindStringSubmatch(line)
		if len(nameMatches) > 0 {
			if currentSSLVersion != "" {
				sslInfo[currentSSLVersion] = ciphers
				ciphers = []SSLCipher{}
			}
			currentSSLVersion = nameMatches[1]
			continue
		}

		matches := tlsRegexp.FindStringSubmatch(line)
		if len(matches) > 0 {
			ciphers = append(ciphers, SSLCipher{
				Name:    matches[1],
				Quality: matches[2],
			})
		}
	}

	if currentSSLVersion != "" {
		sslInfo[currentSSLVersion] = ciphers
	}

	return sslInfo
}
