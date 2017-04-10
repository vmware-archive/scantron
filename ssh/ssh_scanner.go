package ssh

import (
	"encoding/base64"
	"net"
	"strings"

	"github.com/pivotal-cf/scantron"
	"golang.org/x/crypto/ssh"
)

var keyAlgos = []string{
	ssh.KeyAlgoRSA,
	ssh.KeyAlgoDSA,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoED25519,
}

func ScanSSH(host string) ([]scantron.SSHKey, error) {
	sshKeys := []scantron.SSHKey{}

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		encodedKey := base64.StdEncoding.EncodeToString(key.Marshal())
		sshKeys = append(sshKeys, scantron.SSHKey{
			Type: key.Type(),
			Key:  encodedKey,
		})
		return nil
	}

	for _, keyAlgo := range keyAlgos {
		config := &ssh.ClientConfig{
			HostKeyCallback:   hostKeyCallback,
			HostKeyAlgorithms: []string{keyAlgo},
		}

		client, err := ssh.Dial("tcp", host, config)

		if err != nil {
			if !strings.HasPrefix(err.Error(), "ssh:") {
				return nil, err
			}
		} else {
			client.Close()
		}
	}

	return sshKeys, nil
}
