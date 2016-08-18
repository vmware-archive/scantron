package scanner

import (
	"bufio"
	"strconv"
	"strings"
)

type File struct {
	Descriptor string
	Name       string
}

func (f File) Port() (int, bool) {
	parts := strings.Split(f.Name, ":")
	if len(parts) != 2 {
		return 0, false
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}

	return port, true
}

type Process struct {
	CommandName string
	ID          string
	Files       []File
}

func (p Process) HasFileWithPort(port int) bool {
	for _, file := range p.Files {
		if filePort, ok := file.Port(); ok && filePort == port {
			return true
		}
	}
	return false
}

func ParseLSOFOutput(output string) []Process {
	scanner := bufio.NewScanner(strings.NewReader(output))
	processes := []Process{}

	var process *Process
	var file *File
	for scanner.Scan() {
		line := scanner.Text()
		switch line[0] {
		case 'p':
			if process != nil {
				if file != nil {
					process.Files = append(process.Files, *file)
					file = nil
				}
				processes = append(processes, *process)
			}

			process = &Process{
				ID: line[1:],
			}
		case 'c':
			process.CommandName = line[1:]
		case 'f':
			if file != nil {
				process.Files = append(process.Files, *file)
			}

			file = &File{
				Descriptor: line[1:],
			}
		case 'n':
			if file != nil && file.Name != "" {
				process.Files = append(process.Files, *file)
			}

			if file == nil {
				file = &File{}
			}

			file.Name = line[1:]
		}
	}

	if file != nil {
		process.Files = append(process.Files, *file)
	}

	if process != nil {
		processes = append(processes, *process)
	}

	return processes
}
