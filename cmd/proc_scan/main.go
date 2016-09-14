package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	ps "github.com/mitchellh/go-ps"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
)

func getNetstatPorts() []scanner.NetstatPort {
	bs, err := exec.Command("netstat", "-at", "-4", "--numeric-ports", "-u", "-p").Output()
	if err == nil {
		return scanner.ParseNetstatOutputForPort(string(bs))
	}

	return []scanner.NetstatPort{}
}

func main() {
	processes, err := ps.Processes()

	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get process list:", err)
		os.Exit(1)
	}

	netstatPorts := getNetstatPorts()

	jsonProcesses := []scantron.Process{}

	for _, process := range processes {

		pid := process.Pid()

		jsonProcess := scantron.Process{
			CommandName: process.Executable(),
			ID:          pid,
		}

		bs, err := exec.Command("ps", "-e", "-o", "uname:20=", "-f", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error getting user:", err)
			os.Exit(1)
		}
		jsonProcess.User = strings.TrimSpace(string(bs))

		jsonProcess.Cmdline, err = readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error getting cmdline:", err)
			os.Exit(1)
		}

		jsonProcess.Env, err = readFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error getting env:", err)
			os.Exit(1)
		}

		getNetstatOutput := func() []scantron.Port {
			result := []scantron.Port{}

			for _, netstatPort := range netstatPorts {
				if netstatPort.ID == pid {
					result = append(result, netstatPort.Local)
				}
			}

			return result
		}

		ports := []scantron.Port{}
		ports = append(ports, getNetstatOutput()...)
		jsonProcess.Ports = ports
		jsonProcesses = append(jsonProcesses, jsonProcess)
	}

	bs, err := exec.Command(
		"find", "/",
		"-type", "f",
		"-perm", "-o+w",
		"-not", "-path", "/proc/*",
		"-not", "-path", "/sys/*",
		"-not", "-path", "/dev/*",
	).Output()
	findResult := string(bs)
	findLines := strings.Split(findResult, "\n")
	findFiles := []scantron.File{}
	for _, line := range findLines {
		if line != "" {
			findFiles = append(findFiles, scantron.File{
				Path: line,
			})
		}
	}

	systemInfo := scantron.SystemInfo{
		Processes: jsonProcesses,
		Files:     findFiles,
	}

	json.NewEncoder(os.Stdout).Encode(systemInfo)
}

func readFile(path string) ([]string, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return []string{}, err
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
