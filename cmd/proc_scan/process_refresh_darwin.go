// +build !linux

package main

import (
	ps "github.com/keybase/go-ps"
)

func refreshProcess(process ps.Process) error {
	return nil
}
