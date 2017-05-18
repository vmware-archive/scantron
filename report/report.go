package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pivotal-cf/scantron/db"
)

type Report struct {
	Header []string
	Rows   [][]string
}

func (r Report) IsEmpty() bool {
	return len(r.Rows) == 0
}

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

func BuildRootProcessesReport(database *db.Database) (Report, error) {
	rows, err := database.DB().Query(`
	SELECT DISTINCT h.name, po.number, pr.name
    FROM hosts h
      JOIN processes pr
        ON h.id = pr.host_id
      JOIN ports po
        ON po.process_id = pr.id
	WHERE po.state = "LISTEN"
      AND po.address != "127.0.0.1"
      AND pr.user = "root"
      AND pr.name NOT IN ('sshd', 'rpcbind')
    ORDER BY h.name, po.number
	`)
	if err != nil {
		return Report{}, err
	}

	defer rows.Close()

	report := Report{
		Header: []string{"Identity", "Port", "Process Name"},
	}

	for rows.Next() {
		var (
			hostname    string
			processName string
			portNumber  int
		)

		err := rows.Scan(&hostname, &portNumber, &processName)
		if err != nil {
			return Report{}, err
		}

		report.Rows = append(report.Rows, []string{
			hostname,
			fmt.Sprintf("%5d", portNumber),
			processName,
		})
	}

	return report, nil
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
		Header: []string{"Identity", "Port", "Process Name", "Reason"},
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

		isGoodProtocol, isGoodCipher := approvedProtocolsAndCiphers(cs)

		if isGoodProtocol && isGoodCipher {
			continue
		}

		reasons := []string{}

		if !isGoodProtocol {
			reasons = append(reasons, "non-approved protocol(s)")
		}

		if !isGoodCipher {
			reasons = append(reasons, "non-approved cipher(s)")
		}

		report.Rows = append(report.Rows, []string{
			hostname,
			fmt.Sprintf("%5d", portNumber),
			processName,
			strings.Join(reasons, "\n"),
		})
	}
	return report, nil
}

func approvedProtocolsAndCiphers(cs cipherSuites) (bool, bool) {
	isGoodProtocol := true
	isGoodCipher := true

	for protocol, suites := range cs {
		if !goodProtocols.contains(protocol) && len(suites) > 0 {
			isGoodProtocol = false
		}

		for _, s := range suites {
			if !goodCiphers.contains(s) {
				isGoodCipher = false
			}
		}
	}

	return isGoodProtocol, isGoodCipher
}
