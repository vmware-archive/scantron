// +build linux

package process

import (
	ps "github.com/keybase/go-ps"
)

func refreshProcess(process ps.Process) error {
	return process.(*ps.UnixProcess).Refresh()
}
