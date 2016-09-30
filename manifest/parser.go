package manifest

import (
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
		return Manifest{}, err
	}

	return manifest, nil
}
