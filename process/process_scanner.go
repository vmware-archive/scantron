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

func ScanProcesses(logger scanlog.Logger) ([]scantron.Process, error) {
	processes, err := GetProcesses()
	if err != nil {
		return nil, err
	}

	ports := GetPorts()
	for i := range processes {
		portsForPid := ports.LocalPortsForPID(processes[i].PID)

		for j := range portsForPid {

		 if strings.ToUpper(portsForPid[j].State) != "LISTEN" {
			 continue
		 }

		 if portsForPid[j].Protocol == "udp" {
			 continue
		 }

		 portsForPid[j].TLSInformation = getTLSInformation(logger, portsForPid[j])
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

func getTLSInformation(logger scanlog.Logger, port scantron.Port) scantron.TLSInformation {
	portNum := strconv.Itoa(port.Number)

	portLogger := logger.With("port", portNum)

	tlsInformation := scantron.TLSInformation{}

	results, err := tlsscan.Scan(portLogger, "localhost", portNum)
	if err != nil {
		tlsInformation.ScanError = err
		return tlsInformation
	}

	if !results.HasTLS() {
		return tlsInformation
	}

	tlsInformation.CipherInformation = results

	cert, mutual, err := tlsscan.FetchTLSInformation("localhost", portNum)
	if err != nil {
		tlsInformation.ScanError = err
		return tlsInformation
	}

	tlsInformation.Certificate = cert
	tlsInformation.Mutual = mutual

	return tlsInformation
}
