package scanner

import "github.com/pivotal-golang/lager"

type Scanner interface {
	Scan(lager.Logger) error
}

const asciiCheckmark = "\u2713"

type ScannedService struct {
	hostname string
	name     string
	port     int
	ssl      bool
	ip       string
}
