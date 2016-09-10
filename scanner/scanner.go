package scanner

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
)

type Scanner interface {
	Scan(lager.Logger) ([]ScannedService, error)
}

type ScannedService struct {
	IP   string
	Job  string
	Name string
	PID  int
	User string
	Port int

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
