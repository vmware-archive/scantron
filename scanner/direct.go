package scanner

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
	"github.com/pkg/sftp"
)

type direct struct {
	nmapResults scantron.NmapResults
	machine     *scantron.Machine
}

func Direct(nmapResults scantron.NmapResults, machine *scantron.Machine) Scanner {
	return &direct{
		nmapResults: nmapResults,
		machine:     machine,
	}
}

func (d *direct) Scan(logger lager.Logger) ([]ScannedService, error) {
	l := logger.Session("scan")

	var scannedServices []ScannedService
	var auth []ssh.AuthMethod

	if d.machine.Key != nil {
		auth = []ssh.AuthMethod{
			ssh.PublicKeys(d.machine.Key),
		}
	} else {
		auth = []ssh.AuthMethod{
			ssh.Password(d.machine.Password),
		}
	}

	config := &ssh.ClientConfig{
		User: d.machine.Username,
		Auth: auth,
	}

	nmapServices, found := d.nmapResults[d.machine.Address]
	if !found {
		return nil, nil
	}

	endpoint := fmt.Sprintf("%s:22", d.machine.Address)
	endpointLogger := l.Session("dial", lager.Data{
		"endpoint": endpoint,
	})

	conn, err := ssh.Dial("tcp", endpoint, config)
	if err != nil {
		return nil, err
	}

	session, err := conn.NewSession()
	if err != nil {
		endpointLogger.Error("failed-to-create-session", err)
		return nil, err
	}

	bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- lsof -iTCP -sTCP:LISTEN +c0 -FcnL -P -n", d.machine.Password))
	if err != nil {
		endpointLogger.Error("failed-to-run-lsof", err)
		return nil, err
	}

	processes := ParseLSOFOutput(string(bs))

	output, err := d.scanProc(logger, conn)
	if err != nil {
		endpointLogger.Error("failed-to-run-proc-scan", err)
		return nil, err
	}

	cmdMap := d.parseProcOutput(string(output))

	for _, nmapService := range nmapServices {
		for _, process := range processes {
			if process.HasFileWithPort(nmapService.Port) {
				scannedServices = append(scannedServices, ScannedService{
					Job:  d.machine.Address,
					IP:   d.machine.Address,
					Name: process.CommandName,
					PID:  process.ID,
					User: process.User,
					Port: nmapService.Port,
					Cmd:  cmdMap[process.ID],
				})
			}
		}
	}

	return scannedServices, nil
}

func (d *direct) scanProc(logger lager.Logger, conn *ssh.Client) ([]byte, error) {
	sftp, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer sftp.Close()

	srcFile, err := os.Open("./" + "proc_scan")
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer srcFile.Close()

	dstFile, err := sftp.Create("./" + "proc_scan")
	if err != nil {
		fmt.Println("err")
		log.Fatal(err)
		return nil, err
	}
	defer dstFile.Close()
	defer sftp.Remove("./proc_scan")

	dstFile.ReadFrom(srcFile)
	sftp.Chmod("./proc_scan", 0777)

	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}

	return session.Output(fmt.Sprintf("echo %s | sudo -S -- bash ./proc_scan", d.machine.Password))
}

func (d *direct) parseProcOutput(output string) map[string]Cmd {
	cmdMap := make(map[string]Cmd)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		switch line[0] {
		case 'p':
			pid := line[1:]
			scanner.Scan()
			args := scanner.Text()
			scanner.Scan()
			env := scanner.Text()
			envs := strings.Split(env, "\x00")
			entry := Cmd{
				Args: args,
				Envs: envs,
			}
			cmdMap[pid] = entry
		}
	}

	return cmdMap
}
