package commands_test

import (


	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"

)

var _ = Describe("Bosh Scan", func() {
	
	Context("when running bosh-scan", func(){
		
		It("exits with error if director-url and bosh-deployment is not provided", func() {
			session := runCommand("direct-scan", "--serial")

			Expect(session).To(Exit(1))

			Expect(session.Err).To(Say("unknown flag `serial'"))
		})
	})
}) 