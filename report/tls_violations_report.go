package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pivotal-cf/scantron/db"
)

type cipherSuites map[string][]string

type stringSlice []string

func (s stringSlice) contains(str string) bool {
	for _, found := range s {
		if found == str {
			return true
		}
	}
	return false
}

var goodCiphers = stringSlice{
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
}

var goodProtocols = stringSlice{
	"VersionTLS12",
}

func BuildTLSViolationsReport(database *db.Database) (Report, error) {
	rows, err := database.DB().Query(`
    SELECT DISTINCT h.name, po.number, pr.name, t.cipher_suites
    FROM hosts h
      JOIN processes pr
        ON h.id = pr.host_id
      JOIN ports po
        ON po.process_id = pr.id
      JOIN tls_informations t
        ON t.port_id = po.id
    ORDER BY h.name, po.number
	`)
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

	for rows.Next() {
		var (
			hostname         string
			processName      string
			portNumber       int
			cipherSuitesJSON string
		)

		err := rows.Scan(&hostname, &portNumber, &processName, &cipherSuitesJSON)
		if err != nil {
			return Report{}, err
		}

		cs := cipherSuites{}

		err = json.Unmarshal([]byte(cipherSuitesJSON), &cs)
		if err != nil {
			return Report{}, err
		}

		nonApprovedProtocols, nonApprovedCiphers := approvedProtocolsAndCiphers(cs)

		if len(nonApprovedProtocols) == 0 && len(nonApprovedCiphers) == 0 {
			continue
		}

		report.Rows = append(report.Rows, []string{
			hostname,
			fmt.Sprintf("%d", portNumber),
			processName,
			strings.Join(nonApprovedProtocols, " "),
			strings.Join(nonApprovedCiphers, " "),
		})
	}
	return report, nil
}

func approvedProtocolsAndCiphers(cs cipherSuites) ([]string, []string) {
	var nonApprovedProtocols, nonApprovedCiphers []string

	for protocol, cipherSuites := range cs {
		if !goodProtocols.contains(protocol) && len(cipherSuites) > 0 {
			nonApprovedProtocols = append(nonApprovedProtocols, protocol)
		}

		for _, cipher := range cipherSuites {
			if !goodCiphers.contains(cipher) {
				nonApprovedCiphers = append(nonApprovedCiphers, cipher)
			}
		}
	}

	return nonApprovedProtocols, nonApprovedCiphers
}
