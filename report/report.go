package report

import (
	"fmt"
	"io"

	"github.com/olekukonko/tablewriter"
)

type Report struct {
	Header   []string
	Rows     [][]string
	Title    string
	Footnote string
}

func (r Report) IsEmpty() bool {
	return len(r.Rows) == 0
}

func (r Report) WriteTo(writer io.Writer) {
	table := tablewriter.NewWriter(writer)
	table.SetHeader(r.Header)
	table.AppendBulk(r.Rows)

	fmt.Println(r.Title)
	fmt.Println("")
	table.Render()
	fmt.Println("")

	if r.Footnote != "" {
		fmt.Println(r.Footnote)
	}

	fmt.Println("")
}
