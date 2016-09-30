package manifest_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/manifest"
)

var _ = Describe("Parser", func() {
	It("parses the file", func() {
		m, err := manifest.Parse("example.yml")
		Expect(err).NotTo(HaveOccurred())

		Expect(m).To(Equal(manifest.Manifest{
			Hosts: []manifest.Host{
				{
					Name: "host1",
					Processes: []manifest.Process{
						{
							Command: "command1",
							User:    "root",
							Ports:   []manifest.Port{1234, 5678, 9012},
						},
						{
							Command: "command2",
							User:    "user2",
							Ports:   []manifest.Port{8230, 2852},
						},
					},
				},
				{
					Name: "host2",
					Processes: []manifest.Process{
						{
							Command: "command3",
							User:    "user3",
							Ports:   []manifest.Port{9876, 5432},
						},
					},
				},
			},
		}))
	})

	Context("when the file does not exist", func() {
		It("returns an error", func() {
			_, err := manifest.Parse("this/does/not/exist")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when the file is mangled", func() {
		It("returns an error", func() {
			_, err := manifest.Parse("broken.yml")
			Expect(err).To(HaveOccurred())
		})
	})
})
