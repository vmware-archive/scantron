package scanner

import "github.com/pivotal-golang/lager"

type Scanner interface {
	Scan(lager.Logger) ([]ScannedService, error)
}

type ScannedService struct {
	Hostname string
	Name     string
	User     string
	Port     int
	SSL      bool
	IP       string
}
