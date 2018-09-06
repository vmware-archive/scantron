// +build !windows

package netstat

import (
	"bufio"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/pivotal-cf/scantron"
)

type NetstatInfo struct {
	CommandName    string
	PID            string
	LocalAddress   string
	ForeignAddress string
	State          string
	Protocol       string
}

type NetstatPort struct {
	PID  int
	Port scantron.Port
}

type NetstatPorts []NetstatPort

func ParseNetstatOutputForPort(output string) []NetstatPort {
	scanner := bufio.NewScanner(strings.NewReader(output))
	result := []NetstatPort{}

	for scanner.Scan() {
		line := scanner.Text()
		info, valid := parseNetstatLine(line)

		if valid {
			result = append(result, createNetstatPort(info))
		}
	}

	return result
}

func parseNetstatLine(line string) (NetstatInfo, bool) {
	netstat := strings.Fields(line)

	var protocol, localAddress, foreignAddress, state, process string

	if len(netstat) < 6 {
		return NetstatInfo{}, false
	}

	protocol = netstat[0]
	localAddress = netstat[3]
	foreignAddress = netstat[4]

	if len(netstat) == 6 {
		state = ""
		process = netstat[5]
	} else {
		state = netstat[5]
		process = netstat[6]
	}

	switch protocol {
	case "tcp", "tcp6", "udp", "udp6":
		break
	default:
		return NetstatInfo{}, false
	}

	processTokens := strings.Split(process, "/")
	if len(processTokens) < 2 {
		return NetstatInfo{}, false
	}

	pid := processTokens[0]
	cmd := processTokens[1]

	return NetstatInfo{
		CommandName:    cmd,
		PID:            pid,
		LocalAddress:   localAddress,
		ForeignAddress: foreignAddress,
		State:          state,
		Protocol:       protocol,
	}, true
}

func splitAddress(infoAddress string) (string, int) {
	// XXX(cb): In the netstat output IPv6 addresses are shown as :::22 whereas
	// Go parsing requires [::]:22. We try and fix this up here but this is
	// undoubtedly imperfect.
	conformAddr := strings.Replace(infoAddress, "::", "[::]", 1)
	address, port, err := net.SplitHostPort(conformAddr)
	if err != nil {
		log.Printf("failed to split address %q: %s", conformAddr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		number = -1
	}
	return address, number
}

func createPortFromAddress(localAddressAndPort string, foreignAddressAndPort string, protocol string, state string) scantron.Port {
	localAddress, localNumber := splitAddress(localAddressAndPort)
	foreignAddress, foreignNumber := splitAddress(foreignAddressAndPort)
	return scantron.Port{
		Protocol:       protocol,
		Address:        localAddress,
		Number:         localNumber,
		ForeignAddress: foreignAddress,
		ForeignNumber:  foreignNumber,
		State:          state,
	}
}

func createNetstatPort(info NetstatInfo) NetstatPort {
	port := createPortFromAddress(info.LocalAddress, info.ForeignAddress, info.Protocol, info.State)

	id, _ := strconv.Atoi(info.PID)
	return NetstatPort{
		PID:  id,
		Port: port,
	}
}
