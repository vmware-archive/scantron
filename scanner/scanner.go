package scanner

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
)

type Scanner interface {
	Scan(lager.Logger) ([]ScannedHost, error)
}

type ScannedHost struct {
	IP       string
	Job      string
	Services []ScannedService
	Files    []scantron.File
}

type ScannedService struct {
	Name  string
	PID   int
	User  string
	Ports []scantron.Port

	TLSInformation TLSInformation
	Cmd            Cmd
}

type TLSInformation struct {
	Presence          bool
	Certificate       *Certificate
	CipherInformation scantron.CipherInformation
}

type Cmd struct {
	Cmdline []string
	Env     []string
}

func convertToScannedHost(host scantron.SystemInfo, ip string) ScannedHost {
	scannedServices := []ScannedService{}
	for _, process := range host.Processes {
		scannedServices = append(scannedServices, ScannedService{
			Name:  process.CommandName,
			PID:   process.ID,
			User:  process.User,
			Ports: process.Ports,
			Cmd: Cmd{
				Cmdline: process.Cmdline,
				Env:     process.Env,
			},
		})
	}

	return ScannedHost{
		Job:      ip,
		IP:       ip,
		Services: scannedServices,
		Files:    host.Files,
	}
}
