package manifest

import (
	"errors"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

func Parse(filePath string) (Manifest, error) {
	bs, err := ioutil.ReadFile(filePath)
	if err != nil {
		return Manifest{}, err
	}

	var manifest Manifest

	err = yaml.Unmarshal(bs, &manifest)
	if err != nil {
		return Manifest{}, errors.New("incorrect yaml format")
	}

	err = validate(manifest)
	if err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

func validate(m Manifest) error {
	if len(m.Specs) == 0 {
		return errors.New("file is empty")
	}
	for _, spec := range m.Specs {
		if len(spec.Prefix) == 0 {
			return errors.New("prefix undefined")
		} else {
			for _, proc := range spec.Processes {
				if len(proc.Command) == 0 ||
					len(proc.User) == 0 ||
					(len(proc.Ports) == 0 && proc.Ignore == false) {
					return errors.New("process info missing")
				}
			}
		}
	}
	return nil
}
