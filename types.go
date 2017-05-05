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

	TLSInformation TLSInformation `json:"tls_information"`
}

type TLSInformation struct {
	Certificate       *Certificate    `json:"certificate"`
	CipherInformation tlsscan.Results `json:"cipher_information"`
	Mutual            bool            `json:"mutual_tls"`

	ScanError error `json:"scan_error,omitempty"`
}

type Certificate struct {
	Expiration time.Time          `json:"expiration"`
	Bits       int                `json:"bits"`
	Subject    CertificateSubject `json:"subject"`
}

type CertificateSubject struct {
	Country  string `json:"country"`
	Province string `json:"province"`
	Locality string `json:"locality"`

	Organization string `json:"organization"`
	CommonName   string `json:"common_name"`
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

type SSHKey struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

type SystemInfo struct {
	Processes []Process `json:"processes"`
	Files     []File    `json:"files"`
	SSHKeys   []SSHKey  `json:"ssh_keys"`
}

func (p Process) HasFileWithPort(number int) bool {
	for _, port := range p.Ports {
		if number == port.Number {
			return true
		}
	}

	return false
}
