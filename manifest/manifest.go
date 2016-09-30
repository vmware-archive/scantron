package manifest

type Manifest struct {
	Hosts []Host
}

type Host struct {
	Name      string `yaml:"name"`
	Processes []Process
}

type Process struct {
	Command string `yaml:"command"`
	User    string `yaml:"user"`
	Ports   []Port `yaml:"ports"`
}

type Port int

func (h Host) ExpectedPorts() []Port {
	var ports []Port

	for _, proc := range h.Processes {
		ports = append(ports, proc.Ports...)
	}

	return ports
}
