package scanner

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	nmap "github.com/lair-framework/go-nmap"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
	"golang.org/x/crypto/ssh"
)

type direct struct {
	nmapRun   *nmap.NmapRun
	inventory *scantron.Inventory
}

func Direct(nmapRun *nmap.NmapRun, inventory *scantron.Inventory) Scanner {
	return &direct{
		nmapRun:   nmapRun,
		inventory: inventory,
	}
}

func (d *direct) Scan(logger lager.Logger) error {
	l := logger.Session("scan")

	var output []ScannedService
	for _, host := range d.inventory.Hosts {
		config := &ssh.ClientConfig{
			User: host.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(host.Password),
			},
		}

		for _, address := range host.Addresses {
			for _, nmapHost := range d.nmapRun.Hosts {
				if nmapHost.Addresses[0].Addr == address {
					endpoint := fmt.Sprintf("%s:22", address)
					endpointLogger := l.Session("dial", lager.Data{
						"endpoint": endpoint,
					})

					conn, err := ssh.Dial("tcp", endpoint, config)
					if err != nil {
						return err
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

						output = append(output, ScannedService{
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
			ssl = asciiCheckmark
		}

		fmt.Fprintln(wr, fmt.Sprintf("%s\t%s\t%s\t%d\t%s", o.ip, o.hostname, o.name, o.port, ssl))
	}

	err := wr.Flush()
	if err != nil {
		return err
	}

	return nil
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
