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
