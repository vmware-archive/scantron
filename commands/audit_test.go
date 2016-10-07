package commands_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-cf/scantron/audit"
	"github.com/pivotal-cf/scantron/commands"
)

var _ = Describe("Audit", func() {
	Describe("Show Report", func() {
		var (
			err         error
			auditReport audit.AuditResult
		)

		JustBeforeEach(func() {
			err = commands.ShowReport(GinkgoWriter, auditReport)
		})

		Context("When report does not have mismatch", func() {
			BeforeEach(func() {
				auditReport = audit.AuditResult{}
			})

			It("does not error", func() {
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("When report has mismatch", func() {
			BeforeEach(func() {
				auditReport = audit.AuditResult{
					ExtraHosts: []string{
						"host1",
						"host2",
					},
				}
			})

			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
