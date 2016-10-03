package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	ps "github.com/keybase/go-ps"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/netstat"
)

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

		err := refreshProcess(process)
		if err != nil {
			// process has gone away
			continue
		}

		jsonProcess := scantron.Process{
			CommandName: process.Executable(),
			PID:         pid,
			User:        user(pid),
			Cmdline:     cmdline(pid),
			Env:         env(pid),
			Ports:       netstatPorts.LocalPortsForPID(pid),
		}

		jsonProcesses = append(jsonProcesses, jsonProcess)
	}

	jsonFiles := worldWritableFiles()

	systemInfo := scantron.SystemInfo{
		Processes: jsonProcesses,
		Files:     jsonFiles,
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

func getNetstatPorts() netstat.NetstatPorts {
	bs, err := exec.Command("netstat", "-at", "-4", "--numeric-ports", "-u", "-p").Output()
	if err != nil {
		return []netstat.NetstatPort{}
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

func worldWritableFiles() []scantron.File {
	bs, err := exec.Command(
		"find", "/",
		"-path", "/proc", "-prune",
		"-o", "-path", "/sys", "-prune",
		"-o", "-path", "/dev", "-prune",
		"-o", "!", "-readable", "-prune",
		"-o", "-type", "f", "-perm", "-o+w",
		"-print",
	).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get list of world-writable files:", err)
		os.Exit(1)
	}

	findResult := string(bs)
	findLines := strings.Split(findResult, "\n")
	jsonFiles := []scantron.File{}
	for _, line := range findLines {
		if line != "" {
			jsonFiles = append(jsonFiles, scantron.File{
				Path: line,
			})
		}
	}

	return jsonFiles
}
