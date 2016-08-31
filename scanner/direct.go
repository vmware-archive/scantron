package scanner

import (
	"fmt"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type direct struct {
	nmapResults scantron.NmapResults
	machine     *scantron.Machine
}

func Direct(nmapResults scantron.NmapResults, machine *scantron.Machine) Scanner {
	return &direct{
		nmapResults: nmapResults,
		machine:     machine,
	}
}

func (d *direct) Scan(logger lager.Logger) ([]ScannedService, error) {
	l := logger.Session("scan")

	var scannedServices []ScannedService
	var auth []ssh.AuthMethod

	if d.machine.Key != nil {
		auth = []ssh.AuthMethod{
			ssh.PublicKeys(d.machine.Key),
		}
	} else {
		auth = []ssh.AuthMethod{
			ssh.Password(d.machine.Password),
		}
	}

	config := &ssh.ClientConfig{
		User: d.machine.Username,
		Auth: auth,
	}

	nmapServices, found := d.nmapResults[d.machine.Address]
	if !found {
		return nil, nil
	}

	endpoint := fmt.Sprintf("%s:22", d.machine.Address)
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
		return nil, err
	}

	bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- lsof -iTCP -sTCP:LISTEN +c0 -FcnL -P -n", d.machine.Password))
	if err != nil {
		endpointLogger.Error("failed-to-run-lsof", err)
		return nil, err
	}

	processes := ParseLSOFOutput(string(bs))

	for _, nmapService := range nmapServices {
		for _, process := range processes {
			if process.HasFileWithPort(nmapService.Port) {
				scannedServices = append(scannedServices, ScannedService{
					Job:  d.machine.Address,
					IP:   d.machine.Address,
					Name: process.CommandName,
					PID:  process.ID,
					User: process.User,
					Port: nmapService.Port,
					SSL:  nmapService.SSL,
				})
			}
		}
	}

	return scannedServices, nil
}
