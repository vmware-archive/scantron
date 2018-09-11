package scantron

import "golang.org/x/crypto/ssh"

type Host struct {
	Name      string   `yaml:"name"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	Addresses []string `yaml:"addresses"`
}

type Inventory struct {
	Hosts []Host `yaml:"hosts"`
}

type Machine struct {
	Address  string
	Username string
	Password string
	Key      ssh.Signer
	OSName   string
}

var Debug bool

func SetDebug(debug bool) {
	Debug = debug
}