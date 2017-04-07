package scantron

import (
	"fmt"
	"os"
	"time"

	"github.com/pivotal-cf/scantron/tlsscan"
)

type File struct {
	Path        string      `json:"path"`
	Permissions os.FileMode `json:"permissions"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Number   int    `json:"number"`
	State    string `json:"state"`

	TLSInformation TLSInformation
}

type TLSInformation struct {
	Certificate       *Certificate
	CipherInformation tlsscan.Results

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
	PID         int      `json:"pid"`
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
