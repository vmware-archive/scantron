package process

import "github.com/pivotal-cf/scantron"

type SystemResources interface {
	GetProcesses() ([]scantron.Process, error)
	GetPorts() ProcessPorts
}
