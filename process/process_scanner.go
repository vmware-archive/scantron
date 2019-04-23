package process

import (
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/tlsscan"
)

type ProcessPort struct {
	PID  int
	Port scantron.Port
}

type ProcessPorts []ProcessPort

type ProcessScanner struct {
	SysRes  SystemResources
	TlsScan tlsscan.TlsScanner
}

func (ps *ProcessScanner) ScanProcesses(logger scanlog.Logger) ([]scantron.Process, error) {
	processes, err := ps.SysRes.GetProcesses()
	if err != nil {
		return nil, err
	}

	ports := ps.SysRes.GetPorts()
	for i := range processes {
		portsForPid := ports.LocalPortsForPID(processes[i].PID)

		for j := range portsForPid {

			if strings.ToUpper(portsForPid[j].State) != "LISTEN" {
				continue
			}

			if portsForPid[j].Protocol == "udp" {
				continue
			}

			portsForPid[j].TLSInformation = ps.getTLSInformation(logger, portsForPid[j])
		}

		processes[i].Ports = portsForPid
	}

	return processes, nil
}

func (ps ProcessPorts) LocalPortsForPID(pid int) []scantron.Port {
	result := []scantron.Port{}

	for _, nsPort := range ps {
		if nsPort.PID == pid {
			result = append(result, nsPort.Port)
		}
	}

	return result
}

func readFile(path string) ([]string, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	inputs := strings.Split(string(bs), "\x00")
	output := []string{}

	for _, input := range inputs {
		if input != "" {
			output = append(output, input)
		}
	}

	return output, nil
}

func (ps *ProcessScanner) getTLSInformation(logger scanlog.Logger, port scantron.Port) *scantron.TLSInformation {
	portNum := strconv.Itoa(port.Number)

	portLogger := logger.With("port", portNum)

	tlsInformation := &scantron.TLSInformation{}

	results, err := ps.TlsScan.Scan(portLogger, "localhost", portNum)
	if err != nil {
		tlsInformation.ScanError = err
		return tlsInformation
	}

	if !results.HasTLS() {
		return nil
	}

	tlsInformation.CipherInformation = results

	cert, mutual, err := ps.TlsScan.FetchTLSInformation("localhost", portNum)
	if err != nil {
		tlsInformation.ScanError = err
		return tlsInformation
	}

	tlsInformation.Certificate = cert
	tlsInformation.Mutual = mutual

	return tlsInformation
}
