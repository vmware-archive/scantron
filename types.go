package scantron

import (
	"fmt"
	"os"
	"time"
)

type File struct {
	Path           string      `json:"path"`
	Permissions    os.FileMode `json:"permissions"`
	User           string      `json:"user"`
	Group          string      `json:"group"`
	ModifiedTime   time.Time   `json:"modified_time"`
	Size           int64       `json:"size"`
	RegexMatches   []RegexMatch    `json:"regex_matches"`
}

type RegexMatch struct {
	PathRegex string `json:"path_regex"`
	ContentRegex string `json:"content_regex"`
}

type Port struct {
	Protocol        string `json:"protocol"`
	Address         string `json:"address"`
	Number          int    `json:"number"`
	ForeignAddress  string `json:"foreignAddress"`
	ForeignNumber   int    `json:"foreignNumber"`
	State           string `json:"state"`

	TLSInformation  *TLSInformation `json:"tls_information"`
}

type TLSInformation struct {
	Certificate       *Certificate      `json:"certificate"`
	CipherInformation CipherInformation `json:"cipher_information"`
	Mutual            bool              `json:"mutual_tls"`

	ScanError error `json:"scan_error,omitempty"`
}

type FileMatch struct {
	PathRegexes      []string `long:"path" description:"Regexes for file paths"`
	ContentRegexes   []string `long:"content" description:"Regexes for file content"`
	MaxRegexFileSize int64    `long:"max" description:"Max file size to check content against regexes" default:"1048576"` // default 1 MB
}

type CipherInformation map[string][]string

func (c CipherInformation) HasTLS() bool {
	for _, suites := range c {
		if len(suites) != 0 {
			return true
		}
	}

	return false
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
