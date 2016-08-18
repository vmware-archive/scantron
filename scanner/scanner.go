package scanner

import "github.com/pivotal-golang/lager"

type Scanner interface {
	Scan(lager.Logger) ([]ScannedService, error)
}

const asciiCheckmark = "\u2713"

type ScannedService struct {
	Hostname string
	Name     string
	Port     int
	SSL      bool
	IP       string
}
