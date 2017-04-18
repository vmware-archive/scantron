package main

import (
	"fmt"

	"github.com/pivotal-cf/scantron/tls"
)

func main() {
	for _, protocolVersion := range tls.ProtocolVersions {
		for _, cipherSuite := range tls.CipherSuites {
			config := tls.Config{
				Version:     protocolVersion.ID,
				CipherSuite: cipherSuite.ID,
			}

			err := tls.Dial("tcp", "localhost:8443", &config)
			//if err != nil {
			//	fmt.Println(protocolVersion.Name, cipherSuite.Name, err.Error())
			//}

			if err == nil {
				fmt.Println(protocolVersion.Name, cipherSuite.Name)
			}
		}
	}
}
