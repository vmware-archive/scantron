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
	PID  string
	User string
	Port int

	SSL            bool
	SSLInformation scantron.SSLInformation
	TLSCert        *Certificate
}
