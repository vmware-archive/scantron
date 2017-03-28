package commands

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"

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

type SshKeyscanCommand struct {
}

func (s *SshKeyscanCommand) Execute(args []string) error {
	host := args[0]

	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		encodedKey := base64.StdEncoding.EncodeToString(key.Marshal())
		fmt.Println(host, key.Type(), encodedKey)
		return nil
	}

	for _, keyAlgo := range keyAlgos {
		config := &ssh.ClientConfig{
			HostKeyCallback:   hostKeyCallback,
			HostKeyAlgorithms: []string{keyAlgo},
		}

		client, err := ssh.Dial("tcp", addr, config)

		if err != nil {
			if !strings.HasPrefix(err.Error(), "ssh:") {
				return fmt.Errorf("error: %s", err)
			}
		} else {
			client.Close()
		}
	}

	return nil
}
