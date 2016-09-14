package scantron

type File struct {
	Path string `json:"path"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Number   int    `json:"number"`
	State    string `json:"state"`
}

type Process struct {
	CommandName string   `json:"name"`
	ID          int      `json:"id"`
	User        string   `json:"user"`
	Cmdline     []string `json:"cmdline"`
	Env         []string `json:"env"`

	Ports []Port `json:"ports"`
}

type SystemInfo struct {
	Processes []Process `json:"processes"`
	Files     []File    `json:"files"`
}

func (p Process) HasFileWithPort(number int) bool {
	for _, port := range p.Ports {
		if number == port.Number {
			return true
		}
	}

	return false
}
