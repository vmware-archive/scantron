package scantron

import nmap "github.com/lair-framework/go-nmap"

type Service struct {
	Port int
	SSL  bool
}

type NmapResults map[string][]Service

func BuildNmapResults(run *nmap.NmapRun) NmapResults {
	results := NmapResults{}

	for _, host := range run.Hosts {
		services := []Service{}

		for _, port := range host.Ports {
			services = append(services, Service{
				Port: port.PortId,
				SSL:  len(port.Service.Tunnel) > 0,
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
