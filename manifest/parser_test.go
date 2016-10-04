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
			Specs: []manifest.Spec{
				{
					Prefix: "host1",
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
					Prefix: "host2",
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

	Context("when the file has semantic errors", func() {
		It("returns an error when specs is misnamed", func() {
			_, err := manifest.Parse("semantic_err_specs.yml")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("file is empty"))
		})

		It("returns an error when prefix is misnamed", func() {
			_, err := manifest.Parse("semantic_err_prefix.yml")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("prefix undefined"))
		})

		It("returns an error when process info is missing", func() {
			_, err := manifest.Parse("semantic_err_command.yml")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("process info missing"))
		})

		It("returns an error when processes are undefined", func() {
			_, err := manifest.Parse("semantic_err_processes.yml")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("incorrect yaml format"))
		})
	})
})
