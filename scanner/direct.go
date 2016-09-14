package scanner

import (
	"encoding/json"
	"fmt"
	"os"

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

func (d *direct) Scan(logger lager.Logger) ([]ScannedHost, error) {
	l := logger.Session("scan")

	var scannedHosts []ScannedHost
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

	endpoint := fmt.Sprintf("%s:22", d.machine.Address)
	endpointLogger := l.Session("dial", lager.Data{
		"endpoint": endpoint,
	})

	conn, err := ssh.Dial("tcp", endpoint, config)
	if err != nil {
		return nil, err
	}

	filepath := "./proc_scan"

	sftp, err := sftpScanBinary(conn, filepath)
	if err != nil {
		endpointLogger.Error("failed-to-setup-sftp", err)
		return nil, err
	}
	defer sftp.Remove(filepath)

	session, err := conn.NewSession()
	if err != nil {
		endpointLogger.Error("failed-to-create-session", err)
		return nil, err
	}

	bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- %s", d.machine.Password, filepath))
	if err != nil {
		endpointLogger.Error("failed-to-run-proc-scan", err)
		return nil, err
	}

	scannedHost, err := d.decodeScannedHost(bs)
	if err != nil {
		endpointLogger.Error("failed-to-unmarshal-output", err)
	}
	scannedHosts = append(scannedHosts, scannedHost)

	return scannedHosts, nil
}

func (d *direct) decodeScannedHost(bs []byte) (ScannedHost, error) {
	var host scantron.SystemInfo
	err := json.Unmarshal(bs, &host)
	if err != nil {
		return ScannedHost{}, err
	}
	return convertToScannedHost(host, d.machine.Address), nil
}

func sftpScanBinary(conn *ssh.Client, filepath string) (*sftp.Client, error) {
	sftp, err := sftp.NewClient(conn)
	if err != nil {
		return nil, err
	}
	defer sftp.Close()

	srcFile, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer srcFile.Close()

	dstFile, err := sftp.Create(filepath)
	if err != nil {
		return nil, err
	}
	defer dstFile.Close()

	dstFile.ReadFrom(srcFile)
	sftp.Chmod(filepath, 0700)

	return sftp, nil
}
