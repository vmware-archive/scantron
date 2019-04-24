package tlsscan

import (
	"bytes"
	"encoding/csv"
	_ "github.com/pivotal-cf/scantron/statik"
	"github.com/rakyll/statik/fs"
	"strconv"
	"strings"
)

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

type ProtocolVersion struct {
	ID   uint16
	Name string
}

var ProtocolVersions = []ProtocolVersion{
	{ID: VersionSSL30, Name: "VersionSSL30"},
	{ID: VersionTLS10, Name: "VersionTLS10"},
	{ID: VersionTLS11, Name: "VersionTLS11"},
	{ID: VersionTLS12, Name: "VersionTLS12"},
}

type CipherSuite struct {
	ID          uint16
	Name        string
	DTls        bool
	Recommended bool
}

func BuildCipherSuites() ([]CipherSuite, error) {
	cs := []CipherSuite{}

	statikFS, err := fs.New()
	if err != nil {
		return cs, err
	}

	fileBytes, err := fs.ReadFile(statikFS, "/assets/tls-parameters.csv")
	if err != nil {
		return cs, err
	}

	r := csv.NewReader(bytes.NewReader(fileBytes))
	table, err := r.ReadAll()
	if err != nil {
		return cs, err
	}

	// loop over all rows after header
	for i := 1; i < len(table); i++ {
		if table[i][2] == "" || table[i][3] == "" {
			continue
		}

		dtls := table[i][2] == "Y"
		rec := table[i][3] == "Y"
		cid, err := strconv.ParseUint(strings.Replace(table[i][0], ",0x", "", 1), 0, 16)
		if err != nil {
			return cs, err
		}

		cs = append(cs, CipherSuite{uint16(cid), table[i][1], dtls, rec})
	}
	return cs, nil
}
