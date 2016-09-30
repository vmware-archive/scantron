package audit

import (
	"database/sql"
	"strings"

	"github.com/pivotal-cf/scantron/manifest"
)

type AuditResult struct {
	Hosts map[string]HostResult
}

type HostResult struct {
	UnexpectedPorts []Port
}

type Port int

func Audit(db *sql.DB, m manifest.Manifest) (AuditResult, error) {
	result := AuditResult{
		Hosts: make(map[string]HostResult),
	}

	for _, host := range m.Hosts {
		findUnexpectedPorts(db, host, result)
	}

	return result, nil
}

func findUnexpectedPorts(db *sql.DB, host manifest.Host, result AuditResult) error {
	expectedPorts := host.ExpectedPorts()

	args := []interface{}{}
	for _, port := range expectedPorts {
		args = append(args, port)
	}
	args = append(args, host.Name)

	rows, err := db.Query(`
			SELECT hosts.name, ports.number
			FROM ports
				INNER JOIN processes
					ON ports.process_id = processes.id
				INNER JOIN hosts
					ON processes.host_id = hosts.id
			WHERE ports.number NOT IN (`+inPlaceholder(expectedPorts)+`)
				AND ports.state = "LISTEN"
				AND hosts.name LIKE ? || '%'
		`, args...)

	if err != nil {
		return err
	}

	defer rows.Close()

	var hostName string
	var unexpectedPort int

	for rows.Next() {
		err := rows.Scan(&hostName, &unexpectedPort)
		if err != nil {
			return err
		}

		hostResults := result.Hosts[hostName]
		hostResults.UnexpectedPorts = append(hostResults.UnexpectedPorts, Port(unexpectedPort))
		result.Hosts[hostName] = hostResults
	}

	return nil
}

func inPlaceholder(things []manifest.Port) string {
	return strings.Join(strings.Split(strings.Repeat("?", len(things)), ""), ", ")
}
