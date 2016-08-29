package scanner

import (
	"fmt"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type direct struct {
	nmapResults scantron.NmapResults
	inventory   *scantron.Inventory
}

func Direct(nmapResults scantron.NmapResults, inventory *scantron.Inventory) Scanner {
	return &direct{
		nmapResults: nmapResults,
		inventory:   inventory,
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
			nmapServices, found := d.nmapResults[address]
			if !found {
				continue
			}

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

			bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- lsof -iTCP -sTCP:LISTEN +c0 -FcnL -P -n", host.Password))
			if err != nil {
				endpointLogger.Error("failed-to-run-lsof", err)
				continue
			}

			processes := ParseLSOFOutput(string(bs))

			for _, nmapService := range nmapServices {
				for _, process := range processes {
					if process.HasFileWithPort(nmapService.Port) {
						scannedServices = append(scannedServices, ScannedService{
							Hostname: host.Name,
							IP:       address,
							Name:     process.CommandName,
							User:     process.User,
							Port:     nmapService.Port,
							SSL:      nmapService.SSL,
						})
					}
				}
			}
		}
	}

	return scannedServices, nil
}
