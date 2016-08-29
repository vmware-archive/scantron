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
		address := host.Addresses[0].Addr
		services := []Service{}

		for _, port := range host.Ports {
			services = append(services, Service{
				Port: port.PortId,
				SSL:  len(port.Service.Tunnel) > 0,
			})
		}

		results[address] = services
	}

	return results
}
