package scantron

import (
	"fmt"
	"time"
)

type File struct {
	Path string `json:"path"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Number   int    `json:"number"`
	State    string `json:"state"`

	TLSInformation TLSInformation
}

type TLSInformation struct {
	Presence          bool
	Certificate       *Certificate
	CipherInformation CipherInformation

	ScanError error
}

type Certificate struct {
	Expiration time.Time
	Bits       int
	Subject    CertificateSubject
}

type CertificateSubject struct {
	Country  string
	Province string
	Locality string

	Organization string
	CommonName   string
}

func (cs CertificateSubject) String() string {
	return fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/CN=%s", cs.Country, cs.Province, cs.Locality, cs.Organization, cs.CommonName)
}

type Process struct {
	CommandName string   `json:"name"`
	ID          int      `json:"id"`
	User        string   `json:"user"`
	Cmdline     []string `json:"cmdline"`
	Env         []string `json:"env"`

	Ports []Port `json:"ports"`
}

type SystemInfo struct {
	Processes []Process `json:"processes"`
	Files     []File    `json:"files"`
}

func (p Process) HasFileWithPort(number int) bool {
	for _, port := range p.Ports {
		if number == port.Number {
			return true
		}
	}

	return false
}
