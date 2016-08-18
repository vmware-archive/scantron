package scanner_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("LsofParser", func() {
	It("parses a single process with a single file correctly", func() {
		input := `p4115
cpostgres
f6
n127.0.0.1:5432
`
		Expect(scanner.ParseLSOFOutput(input)).To(Equal([]scanner.Process{
			{
				CommandName: "postgres",
				ID:          "4115",
				Files: []scanner.File{
					{
						Descriptor: "6",
						Name:       "127.0.0.1:5432",
					},
				},
			},
		}))
	})

	It("parses a single process with no file descriptor correctly", func() {
		input := `p4115
cpostgres
n127.0.0.1:5432
`
		Expect(scanner.ParseLSOFOutput(input)).To(Equal([]scanner.Process{
			{
				CommandName: "postgres",
				ID:          "4115",
				Files: []scanner.File{
					{
						Name: "127.0.0.1:5432",
					},
				},
			},
		}))
	})

	It("parses a single process with multiple files correctly", func() {
		input := `p4115
cpostgres
f6
n127.0.0.1:5432
f7
n127.0.0.1:5433
`
		Expect(scanner.ParseLSOFOutput(input)).To(Equal([]scanner.Process{
			{
				CommandName: "postgres",
				ID:          "4115",
				Files: []scanner.File{
					{
						Descriptor: "6",
						Name:       "127.0.0.1:5432",
					},
					{
						Descriptor: "7",
						Name:       "127.0.0.1:5433",
					},
				},
			},
		}))
	})

	It("parses multiple processes with multiple files correctly", func() {
		input := `p4115
cpostgres
f6
n127.0.0.1:5432
f7
n127.0.0.1:5433
p6108
csshd
f3
n*:22
f4
n*:22
`
		Expect(scanner.ParseLSOFOutput(input)).To(Equal([]scanner.Process{
			{
				CommandName: "postgres",
				ID:          "4115",
				Files: []scanner.File{
					{
						Descriptor: "6",
						Name:       "127.0.0.1:5432",
					},
					{
						Descriptor: "7",
						Name:       "127.0.0.1:5433",
					},
				},
			},
			{
				CommandName: "sshd",
				ID:          "6108",
				Files: []scanner.File{
					{
						Descriptor: "3",
						Name:       "*:22",
					},
					{
						Descriptor: "4",
						Name:       "*:22",
					},
				},
			},
		}))
	})

	It("parses multiple processes with multiple files with no file descriptor correctly", func() {
		input := `p18929
ctsa
n*:2222
n*:38283
n*:58804
n*:59560
p19278
catc
n*:8080
n127.0.0.1:8079
`
		Expect(scanner.ParseLSOFOutput(input)).To(Equal([]scanner.Process{
			{
				CommandName: "tsa",
				ID:          "18929",
				Files: []scanner.File{
					{Name: "*:2222"},
					{Name: "*:38283"},
					{Name: "*:58804"},
					{Name: "*:59560"},
				},
			},
			{
				CommandName: "atc",
				ID:          "19278",
				Files: []scanner.File{
					{Name: "*:8080"},
					{Name: "127.0.0.1:8079"},
				},
			},
		}))
	})
})
