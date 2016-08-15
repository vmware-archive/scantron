package scantron

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/lair-framework/go-nmap"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

const checkmark = "\u2713"

type Host struct {
	Name      string   `yaml:"name"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	Addresses []string `yaml:"addresses"`
}

type Inventory struct {
	Hosts []Host `yaml:"hosts"`
}

type service struct {
	hostname string
	name     string
	port     int
	ssl      bool
	ip       string
}

func Scan(logger lager.Logger, nmapRun *nmap.NmapRun, inventory *Inventory) {
	l := logger.Session("scan")

	var output []service
	for _, host := range inventory.Hosts {
		config := &ssh.ClientConfig{
			User: host.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(host.Password),
			},
		}

		for _, address := range host.Addresses {
			for _, nmapHost := range nmapRun.Hosts {
				if nmapHost.Addresses[0].Addr == address {
					endpoint := fmt.Sprintf("%s:22", address)
					endpointLogger := l.Session("dial", lager.Data{
						"endpoint": endpoint,
					})

					conn, err := ssh.Dial("tcp", endpoint, config)
					if err != nil {
						endpointLogger.Error("failed", err)
						return
					}

					endpointLogger.Debug("done")

					for _, port := range nmapHost.Ports {
						portLogger := endpointLogger.WithData(lager.Data{
							"port": port.PortId,
						})

						session, err := conn.NewSession()
						if err != nil {
							portLogger.Error("failed-to-create-session", err)
							continue
						}

						bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- lsof +c 0 -i :%d", host.Password, port.PortId))
						if err != nil {
							// the lsof session may fail for things like nfs; try rpcinfo,
							// ignoring original error
							session, err := conn.NewSession()
							if err != nil {
								portLogger.Error("failed-to-create-session", err)
								continue
							}

							bs, err = session.Output("rpcinfo -p")
							if err != nil {
								portLogger.Error("failed-to-exec", err)
								continue
							}
						}

						output = append(output, service{
							hostname: host.Name,
							ip:       address,
							name:     serviceName(bs, port.PortId),
							port:     port.PortId,
							ssl:      len(port.Service.Tunnel) > 0,
						})
					}
				}
			}
		}
	}

	wr := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

	fmt.Fprintln(wr, strings.Join([]string{"IP Address", "Job", "Service", "Port", "SSL"}, "\t"))

	for _, o := range output {
		ssl := ""
		if o.ssl {
			ssl = checkmark
		}

		fmt.Fprintln(wr, fmt.Sprintf("%s\t%s\t%s\t%d\t%s", o.ip, o.hostname, o.name, o.port, ssl))
	}

	err := wr.Flush()
	if err != nil {
		log.Fatalf("failed to print output: %s", err.Error())
	}
}

var commandLineRegexp = regexp.MustCompile(`^COMMAND`)

func serviceName(output []byte, port int) string {
	lsof := lsofServiceName(output)
	if lsof != "" {
		return lsof
	}

	rpcInfo := rpcInfoServiceName(output, port)
	if rpcInfo != "" {
		return rpcInfo
	}

	if port > 60000 {
		return "cloud foundry app"
	}

	return "unknown"
}

func lsofServiceName(output []byte) string {
	lines := bytes.Split(output, []byte("\n"))

	if !commandLineRegexp.Match(lines[0]) {
		return ""
	}

	var service string
	fmt.Sscanf(string(lines[1]), "%s ", &service)

	if service == "" {
		return ""
	}

	return service
}

func rpcInfoServiceName(output []byte, port int) string {
	lines := bytes.Split(output, []byte("\n"))

	var (
		foundPort            int
		service              string
		vers, proto, program string
	)

	for _, line := range lines[1:] {
		fmt.Sscanf(string(line), "%s %s %s %d %s", &program, &vers, &proto, &foundPort, &service)
		if foundPort == port {
			return service
		}
	}

	return ""
}
