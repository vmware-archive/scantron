package report

type Report struct {
	Header []string
	Rows   [][]string
}

func (r Report) IsEmpty() bool {
	return len(r.Rows) == 0
}
