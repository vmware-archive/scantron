package audit

import (
	"database/sql"
	"strings"

	"github.com/pivotal-cf/scantron/manifest"
)

type AuditResult struct {
	Hosts           map[string]HostResult
	ExtraHosts      []string
	MissingHostType []string
}

func (r AuditResult) OK() bool {
	for _, hr := range r.Hosts {
		if !hr.OK() {
			return false
		}
	}

	return len(r.ExtraHosts) == 0 && len(r.MissingHostType) == 0
}

type HostResult struct {
	MismatchedProcesses []MismatchedProcess
	MissingProcesses    []string
	UnexpectedPorts     []Port
	MissingPorts        []Port
}

func (hr HostResult) OK() bool {
	return len(hr.MismatchedProcesses) == 0 &&
		len(hr.MissingProcesses) == 0 &&
		len(hr.UnexpectedPorts) == 0 &&
		len(hr.MissingPorts) == 0
}

type MismatchedProcess struct {
	Command string

	Field    string
	Actual   string
	Expected string
}

type Port int

func Audit(db *sql.DB, m manifest.Manifest) (AuditResult, error) {
	result := AuditResult{
		Hosts: make(map[string]HostResult),
	}
	missing, extras, err := lookForMissingAndExtraHosts(db, m.Hosts)
	if err != nil {
		return AuditResult{}, err
	}

	result.ExtraHosts = extras
	result.MissingHostType = missing

	for _, host := range m.Hosts {
		missingProcs, err := lookForMissingProcesses(db, host)
		if err != nil {
			return AuditResult{}, err
		}

		missingPorts, err := lookForMissingPorts(db, host)
		if err != nil {
			return AuditResult{}, err
		}

		hostResult := result.Hosts[host.Name]
		hostResult.MissingPorts = missingPorts
		hostResult.MissingProcesses = missingProcs
		result.Hosts[host.Name] = hostResult

		err = findUnexpectedPorts(db, host, result)
		if err != nil {
			return AuditResult{}, err
		}

		err = verifyProcessUsers(db, host, result)
		if err != nil {
			return AuditResult{}, err
		}
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
			WHERE ports.number NOT IN (`+inPlaceholder(len(expectedPorts))+`)
				AND ports.state = "LISTEN"
				AND ports.address != "127.0.0.1"
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

func inPlaceholder(count int) string {
	return strings.Join(strings.Split(strings.Repeat("?", count), ""), ", ")
}

func lookForMissingAndExtraHosts(db *sql.DB, manifestHosts []manifest.Host) ([]string, []string, error) {
	rows, err := db.Query(`
		SELECT hosts.name
		FROM hosts
	`)

	if err != nil {
		return nil, nil, err
	}

	defer rows.Close()

	reportHosts := []string{}

	for rows.Next() {
		var reportHost string
		err := rows.Scan(&reportHost)
		if err != nil {
			return nil, nil, err
		}

		reportHosts = append(reportHosts, reportHost)
	}

	extras := []string{}
	missings := []string{}

	for _, reportHost := range reportHosts {
		found := false

		for _, manifestHost := range manifestHosts {
			if strings.HasPrefix(reportHost, manifestHost.Name) {
				found = true
			}
		}

		if !found {
			extras = append(extras, reportHost)
		}
	}

	for _, manifestHost := range manifestHosts {
		found := false

		for _, reportHost := range reportHosts {
			if strings.HasPrefix(reportHost, manifestHost.Name) {
				found = true
			}
		}

		if !found {
			missings = append(missings, manifestHost.Name)
		}
	}

	return missings, extras, nil
}

func verifyProcessUsers(db *sql.DB, host manifest.Host, result AuditResult) error {
	for _, proc := range host.Processes {
		rows, err := db.Query(`
			SELECT DISTINCT hosts.name, processes.user, processes.name
			FROM processes
				INNER JOIN hosts
					ON processes.host_id = hosts.id
				INNER JOIN ports
					ON processes.id = ports.process_id
			WHERE processes.user != ?
				AND processes.name = ?
				AND hosts.name LIKE ? || '%'
		`, proc.User, proc.Command, host.Name)

		if err != nil {
			return err
		}

		defer rows.Close()

		var hostName, processUser, processCommand string

		for rows.Next() {
			err := rows.Scan(&hostName, &processUser, &processCommand)
			if err != nil {
				return err
			}

			hostResults := result.Hosts[hostName]
			processResult := MismatchedProcess{
				Command:  processCommand,
				Field:    "user",
				Actual:   processUser,
				Expected: proc.User,
			}

			hostResults.MismatchedProcesses = append(hostResults.MismatchedProcesses, processResult)
			result.Hosts[hostName] = hostResults
		}
	}

	return nil
}

func lookForMissingProcesses(db *sql.DB, host manifest.Host) ([]string, error) {
	missingCommands := []string{}

	for _, proc := range host.Processes {
		var count int

		err := db.QueryRow(`
			SELECT COUNT(processes.name)
			FROM processes
				JOIN hosts
					ON processes.host_id = hosts.id
			WHERE processes.name = ?
				AND hosts.name LIKE ? || '%'
		`, proc.Command, host.Name).Scan(&count)

		if err != nil {
			return nil, err
		}

		if count == 0 {
			missingCommands = append(missingCommands, proc.Command)
		}
	}

	return missingCommands, nil
}

func lookForMissingPorts(db *sql.DB, host manifest.Host) ([]Port, error) {
	missingPorts := []Port{}

	for _, port := range host.ExpectedPorts() {
		var count int

		err := db.QueryRow(`
			SELECT COUNT(ports.number)
			FROM processes
				JOIN ports
					ON processes.id = ports.process_id
				JOIN hosts
					ON processes.host_id = hosts.id
			WHERE ports.number = ?
				AND hosts.name LIKE ? || '%'
		`, port, host.Name).Scan(&count)

		if err != nil {
			return nil, err
		}

		if count == 0 {
			missingPorts = append(missingPorts, Port(port))
		}
	}

	return missingPorts, nil
}
