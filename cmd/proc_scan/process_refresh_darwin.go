// +build !linux

package main

import (
	ps "github.com/mitchellh/go-ps"
)

func refreshProcess(process ps.Process) error {
	return nil
}
