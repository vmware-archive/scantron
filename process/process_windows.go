// +build windows

package process

import (
	"encoding/json"
	"fmt"
	"github.com/pivotal-cf/scantron"
	"os/exec"
	"strings"
)

type WinProcess struct {
	CommandName string   `json:"name"`
	PID         int      `json:"pid"`
	User        string   `json:"user"`
	Cmdline     string `json:"cmdline"`
}

type WinEnv struct {
	Key string `json:"Key"`
	Value string `json:"Value"`
}

type WinPort struct {
	LocalAddress string `json:"localaddress"`
	LocalPort int `json:"localport"`
	RemoteAddress string `json:"remoteaddress"`
	RemotePort int `json:"remoteport"`
	OwningProcess int `json:"owningprocess"`
	State string `json:"state"`
}
type SystemResourceImpl struct {

}
func (s *SystemResourceImpl) GetProcesses() ([]scantron.Process, error) {

	cmd := exec.Command("powershell", "get-wmiobject win32_process | select @{Name='pid'; Expression={$_.ProcessId}}, @{Name='name'; Expression={$_.Name}}, @{Name='user'; Expression={$_.GetOwner().User }}, @{Name='cmdline'; Expression={$_.Commandline}} | ConvertTo-Json")

	out, e := cmd.Output()
	if e != nil {
		return nil, e
	}

	var rawProcesses = []WinProcess{}
	err := json.Unmarshal(out, &rawProcesses)
	if err != nil {
		return nil, err
	}

	processes := []scantron.Process{}
	for _, rawProcess := range rawProcesses {
		pid := rawProcess.PID
		process := scantron.Process{
			CommandName: rawProcess.CommandName,
			PID:         pid,
			User:        rawProcess.User,
			Cmdline:     strings.Split(rawProcess.Cmdline, " "),
			Env:         getEnv(pid),
		}
		processes = append(processes, process)
	}

	return processes, nil
}

func (s *SystemResourceImpl) GetPorts() ProcessPorts {
	cmd := exec.Command("powershell", "get-netudpendpoint | select localaddress,localport,owningprocess| convertto-json")
	out, e := cmd.Output()
	if e != nil {
		return nil
	}

	var rawUdp = []WinPort{}
	err := json.Unmarshal(out, &rawUdp)

	if err != nil {
		return nil
	}

	cmd = exec.Command("powershell", "get-nettcpconnection | select @{Name='state';Expression={$_.State.ToString()}},localaddress,localport,remoteaddress,remoteport,owningprocess | convertto-json")
	out, e = cmd.Output()
	if e != nil {
		return nil
	}

	var rawTcp = []WinPort{}
	err = json.Unmarshal(out, &rawTcp)

	if err != nil {
		return nil
	}

	ports := []ProcessPort{}
	for _, p := range rawUdp {
		ports = append(ports, ProcessPort{
			PID: p.OwningProcess,
			Port: scantron.Port {
				Protocol: "udp",
				Address: p.LocalAddress,
				Number: p.LocalPort,
			},
		})
	}
	for _, p := range rawTcp {
		ports = append(ports, ProcessPort{
			PID: p.OwningProcess,
			Port: scantron.Port {
				Protocol: "tcp",
				Address: p.LocalAddress,
				Number: p.LocalPort,
				ForeignAddress: p.RemoteAddress,
				ForeignNumber: p.RemotePort,
				State: p.State, // FIXME normalization with netstat?
			},
		})
	}

	return ports
}

func getEnv(pid int) []string {
	cmd := exec.Command("powershell", fmt.Sprintf("(get-process -id %d).StartInfo.EnvironmentVariables | Convertto-json", pid))

	out, e := cmd.Output()
	if e != nil {
		return nil
	}

	var rawVars = []WinEnv{}
	err := json.Unmarshal(out, &rawVars)

	if err != nil {
		return nil
	}

	env := []string{}
	for _, v := range rawVars {
		env = append(env, fmt.Sprintf("%s=%s", v.Key, v.Value))
	}

	return env
}