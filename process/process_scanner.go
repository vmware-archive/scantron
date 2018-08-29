package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/keybase/go-ps"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/netstat"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/tlsscan"
)

func ScanProcesses(logger scanlog.Logger) ([]scantron.Process, error) {
	rawProcesses, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	netstatPorts := getNetstatPorts()

	processes := []scantron.Process{}

	for _, rawProcess := range rawProcesses {
		pid := rawProcess.Pid()

		err := refreshProcess(rawProcess)
		if err != nil {
			// process has gone away
			continue
		}

		ports := netstatPorts.LocalPortsForPID(pid)

		for i := range ports {
			port := ports[i]

			if port.State != "LISTEN" {
				continue
			}

			if port.Protocol == "udp" {
				continue
			}

			port.TLSInformation = getTLSInformation(logger, port)

			ports[i] = port
		}

		process := scantron.Process{
			CommandName: rawProcess.Executable(),
			PID:         pid,
			User:        user(pid),
			Cmdline:     cmdline(pid),
			Env:         env(pid),
			Ports:       ports,
		}

		processes = append(processes, process)
	}

	return processes, nil
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

func getNetstatPorts() netstat.NetstatPorts {
	bs, err := exec.Command("netstat", "-at", "-4", "-6", "--numeric-ports", "-u", "-p").Output()
	if err != nil {
		return nil
	}

	return netstat.ParseNetstatOutputForPort(string(bs))
}

func user(pid int) string {
	bs, err := exec.Command("ps", "-e", "-o", "uname:20=", "-f", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error getting user:", err)
		os.Exit(1)
	}

	return strings.TrimSpace(string(bs))
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

func cmdline(pid int) []string {
	cmdline, err := readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error getting cmdline:", err)
		os.Exit(1)
	}

	return cmdline
}

func env(pid int) []string {
	env, err := readFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error getting env:", err)
		os.Exit(1)
	}

	return env
}
