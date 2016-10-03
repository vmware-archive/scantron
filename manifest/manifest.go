package manifest

type Manifest struct {
	Specs []Spec `yaml:"specs"`
}

type Spec struct {
	Prefix    string `yaml:"prefix"`
	Processes []Process
}

type Process struct {
	Command string `yaml:"command"`
	User    string `yaml:"user"`
	Ports   []Port `yaml:"ports"`
}

type Port int

func (h Spec) ExpectedPorts() []Port {
	var ports []Port

	for _, proc := range h.Processes {
		ports = append(ports, proc.Ports...)
	}

	return ports
}

func (h Spec) ExpectedCommands() []string {
	var commands []string

	for _, proc := range h.Processes {
		commands = append(commands, proc.Command)
	}

	return commands
}
