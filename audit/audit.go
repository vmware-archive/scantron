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

type AuditInput map[string]manifest.Spec

func Audit(db *sql.DB, m manifest.Manifest) (AuditResult, error) {
	result := AuditResult{
		Hosts: make(map[string]HostResult),
	}

	input, err := mapHostnameToSpec(db, m)
	if err != nil {
		return AuditResult{}, err
	}

	missing, extras, err := lookForMissingAndExtraHosts(db, m.Specs)
	if err != nil {
		return AuditResult{}, err
	}

	result.ExtraHosts = extras
	result.MissingHostType = missing

	for host, spec := range input {
		hostResult, err := auditHost(db, host, spec)
		if err != nil {
			return AuditResult{}, err
		}

		result.Hosts[host] = hostResult
	}

	return result, nil
}

func auditHost(db *sql.DB, host string, spec manifest.Spec) (HostResult, error) {
	missingProcs, err := lookForMissingProcesses(db, host, spec)
	if err != nil {
		return HostResult{}, err
	}

	missingPorts, err := lookForMissingPorts(db, host, spec)
	if err != nil {
		return HostResult{}, err
	}

	unexpectedPorts, err := findUnexpectedPorts(db, host, spec)
	if err != nil {
		return HostResult{}, err
	}

	mismatchedProcesses, err := verifyProcessUsers(db, host, spec)
	if err != nil {
		return HostResult{}, err
	}

	return HostResult{
		MissingProcesses:    missingProcs,
		MissingPorts:        missingPorts,
		UnexpectedPorts:     unexpectedPorts,
		MismatchedProcesses: mismatchedProcesses,
	}, nil
}

func mapHostnameToSpec(db *sql.DB, m manifest.Manifest) (AuditInput, error) {
	input := AuditInput{}

	for _, spec := range m.Specs {
		rows, err := db.Query(`
			SELECT hosts.name
			FROM hosts
			WHERE hosts.name LIKE ? || '%'
		`, spec.Prefix)

		if err != nil {
			return AuditInput{}, err
		}

		defer rows.Close()

		var hostName string

		for rows.Next() {
			err := rows.Scan(&hostName)
			if err != nil {
				return AuditInput{}, err
			}

			input[hostName] = spec
		}
	}

	return input, nil
}

func findUnexpectedPorts(db *sql.DB, host string, spec manifest.Spec) ([]Port, error) {
	expectedPorts := spec.ExpectedPorts()

	args := []interface{}{}
	for _, port := range expectedPorts {
		args = append(args, port)
	}
	args = append(args, host)

	rows, err := db.Query(`
		SELECT ports.number, processes.name
		FROM ports
			INNER JOIN processes
				ON ports.process_id = processes.id
			INNER JOIN hosts
				ON processes.host_id = hosts.id
		WHERE ports.number NOT IN (`+inPlaceholder(len(expectedPorts))+`)
			AND ports.state = "LISTEN"
			AND ports.address != "127.0.0.1"
			AND hosts.name = ?
	`, args...)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var unexpectedPorts []Port
	var unexpectedPort int
	var processName string

	for rows.Next() {
		err := rows.Scan(&unexpectedPort, &processName)
		if err != nil {
			return nil, err
		}

		if spec.ShouldIgnorePortsForCommand(processName) {
			continue
		}

		unexpectedPorts = append(unexpectedPorts, Port(unexpectedPort))
	}

	return unexpectedPorts, nil
}

func inPlaceholder(count int) string {
	return strings.Join(strings.Split(strings.Repeat("?", count), ""), ", ")
}

func lookForMissingAndExtraHosts(db *sql.DB, manifestHosts []manifest.Spec) ([]string, []string, error) {
	rows, err := db.Query(`SELECT hosts.name FROM hosts`)

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
			if strings.HasPrefix(reportHost, manifestHost.Prefix) {
				found = true
				break
			}
		}

		if !found {
			extras = append(extras, reportHost)
		}
	}

	for _, manifestHost := range manifestHosts {
		found := false

		for _, reportHost := range reportHosts {
			if strings.HasPrefix(reportHost, manifestHost.Prefix) {
				found = true
				break
			}
		}

		if !found {
			missings = append(missings, manifestHost.Prefix)
		}
	}

	return missings, extras, nil
}

func verifyProcessUsers(db *sql.DB, host string, spec manifest.Spec) ([]MismatchedProcess, error) {
	mismatched := []MismatchedProcess{}

	for _, proc := range spec.Processes {
		rows, err := db.Query(`
			SELECT DISTINCT processes.user, processes.name
			FROM processes
				INNER JOIN hosts
					ON processes.host_id = hosts.id
				INNER JOIN ports
					ON processes.id = ports.process_id
			WHERE processes.user != ?
				AND processes.name = ?
				AND hosts.name = ?
		`, proc.User, proc.Command, host)

		if err != nil {
			return nil, err
		}

		defer rows.Close()

		var processUser, processCommand string

		for rows.Next() {
			err := rows.Scan(&processUser, &processCommand)
			if err != nil {
				return nil, err
			}

			mismatched = append(mismatched, MismatchedProcess{
				Command:  processCommand,
				Field:    "user",
				Actual:   processUser,
				Expected: proc.User,
			})
		}
	}

	return mismatched, nil
}

func lookForMissingProcesses(db *sql.DB, host string, spec manifest.Spec) ([]string, error) {
	missingCommands := []string{}

	for _, command := range spec.ExpectedCommands() {
		var count int

		err := db.QueryRow(`
			SELECT COUNT(processes.name)
			FROM processes
				JOIN hosts
					ON processes.host_id = hosts.id
			WHERE processes.name = ?
				AND hosts.name = ?
		`, command, host).Scan(&count)

		if err != nil {
			return nil, err
		}

		if count == 0 {
			missingCommands = append(missingCommands, command)
		}
	}

	return missingCommands, nil
}

func lookForMissingPorts(db *sql.DB, host string, spec manifest.Spec) ([]Port, error) {
	missingPorts := []Port{}

	for _, port := range spec.ExpectedPorts() {
		var count int

		err := db.QueryRow(`
			SELECT COUNT(ports.number)
			FROM processes
				JOIN ports
					ON processes.id = ports.process_id
				JOIN hosts
					ON processes.host_id = hosts.id
			WHERE ports.number = ?
				AND hosts.name = ?
		`, port, host).Scan(&count)

		if err != nil {
			return nil, err
		}

		if count == 0 {
			missingPorts = append(missingPorts, Port(port))
		}
	}

	return missingPorts, nil
}
