package report

import (
	"fmt"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/tlsscan"
	"strings"
)

type stringSlice []string

func (s stringSlice) contains(str string) bool {
	for _, found := range s {
		if found == str {
			return true
		}
	}
	return false
}

var goodSuites = stringSlice{
	"VersionTLS12",
}

func buildGoodCiphers() (stringSlice, error) {
	allCiphers, err := tlsscan.BuildCipherSuites()
	if err != nil {
		return nil, err
	}

	goodCiphers := make(stringSlice, 0)
	for _, c := range allCiphers {
		if c.Recommended {
			goodCiphers = append(goodCiphers, c.Name)
		}
	}
	return goodCiphers, nil
}

func BuildTLSViolationsReport(database *db.Database) (Report, error) {
	goodCiphers, err := buildGoodCiphers()
	if err != nil {
		return Report{}, err
	}
	query := fmt.Sprintf(`SELECT DISTINCT h.name, po.number, pr.name, s.suite, c.cipher
	FROM hosts h
	JOIN processes pr
	ON h.id = pr.host_id
	JOIN ports po
	ON po.process_id = pr.id
	JOIN tls_certificates t
	ON t.port_id = po.id
	JOIN certificate_to_ciphersuite ctc
	ON t.id = ctc.certificate_id
	JOIN tls_suites s
	ON ctc.suite_id = s.id
	JOIN tls_ciphers c
	ON ctc.cipher_id = c.id
	WHERE s.suite NOT IN(%s) OR c.cipher NOT IN(%s)
	ORDER BY h.name, po.number`, "'"+strings.Join(goodSuites, "','")+"'", "'"+strings.Join(goodCiphers, "','")+"'") // sql binding doesn't play nice with array args
	rows, err := database.DB().Query(query)

	if err != nil {
		return Report{}, err
	}

	defer rows.Close()

	report := Report{
		Title: "Processes using non-approved SSL/TLS settings:",
		Header: []string{
			"Identity",
			"Port",
			"Process Name",
			"Non-approved Protocol(s)",
			"Non-approved Cipher(s)",
		},
		Footnote: "If this is not an internal endpoint then please check with your PM and the security team before applying this change. This change is not backwards compatible.",
	}

	type Host struct {
		hostname    string
		portNumber  int
		processName string
	}

	type cipherSuites struct {
		suites  stringSlice
		ciphers stringSlice
	}

	var hostMap = map[Host]cipherSuites{}

	for rows.Next() {
		var (
			hostname    string
			processName string
			portNumber  int
			suite       string
			cipher      string
		)

		err := rows.Scan(&hostname, &portNumber, &processName, &suite, &cipher)
		if err != nil {
			return Report{}, err
		}

		host := Host{
			hostname,
			portNumber,
			processName,
		}

		cs := hostMap[host]
		if cs.suites == nil {
			cs.suites = []string{}
			cs.ciphers = []string{}
		}
		if !goodSuites.contains(suite) && !cs.suites.contains(suite) {
			cs.suites = append(cs.suites, suite)
		}
		if !goodCiphers.contains(cipher) && !cs.ciphers.contains(cipher) {
			cs.ciphers = append(cs.ciphers, cipher)
		}
		hostMap[host] = cs
	}

	for host, cs := range hostMap {
		report.Rows = append(report.Rows, []string{
			host.hostname,
			fmt.Sprintf("%d", host.portNumber),
			host.processName,
			strings.Join(cs.suites, " "),
			strings.Join(cs.ciphers, " "),
		})
	}
	return report, nil
}
