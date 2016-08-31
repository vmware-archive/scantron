package scanner

import "github.com/pivotal-golang/lager"

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

	SSL     bool
	TLSCert *Certificate
}
