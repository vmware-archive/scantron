package scanner

import (
	"fmt"

	nmap "github.com/lair-framework/go-nmap"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type direct struct {
	nmapRun   *nmap.NmapRun
	inventory *scantron.Inventory
}

func Direct(nmapRun *nmap.NmapRun, inventory *scantron.Inventory) Scanner {
	return &direct{
		nmapRun:   nmapRun,
		inventory: inventory,
	}
}

func (d *direct) Scan(logger lager.Logger) ([]ScannedService, error) {
	l := logger.Session("scan")

	var scannedServices []ScannedService
	for _, host := range d.inventory.Hosts {
		config := &ssh.ClientConfig{
			User: host.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(host.Password),
			},
		}

		for _, address := range host.Addresses {
			for _, nmapHost := range d.nmapRun.Hosts {
				if nmapHost.Addresses[0].Addr == address {
					endpoint := fmt.Sprintf("%s:22", address)
					endpointLogger := l.Session("dial", lager.Data{
						"endpoint": endpoint,
					})

					conn, err := ssh.Dial("tcp", endpoint, config)
					if err != nil {
						return nil, err
					}

					session, err := conn.NewSession()
					if err != nil {
						endpointLogger.Error("failed-to-create-session", err)
						continue
					}

					bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- lsof -l -iTCP -sTCP:LISTEN +c0 -FcnL -P -n", host.Password))
					if err != nil {
						endpointLogger.Error("failed-to-run-lsof", err)
						continue
					}

					processes := ParseLSOFOutput(string(bs))

					for _, nmapPort := range nmapHost.Ports {
						for _, process := range processes {
							if process.HasFileWithPort(nmapPort.PortId) {
								scannedServices = append(scannedServices, ScannedService{
									Hostname: host.Name,
									IP:       address,
									Name:     process.CommandName,
									Port:     nmapPort.PortId,
									SSL:      len(nmapPort.Service.Tunnel) > 0,
								})
							}
						}
					}
				}
			}
		}
	}

	return scannedServices, nil
}
