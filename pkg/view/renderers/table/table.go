package table

import (
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
	"github.com/rodaine/table"
)

type tableRenderer struct{}

func NewTableRender() renderers.Renderer {
	return &tableRenderer{}
}

func (r *tableRenderer) Render(w io.Writer, items []any) error {
	headers, records, err := renderers.BuildRecords(items)
	if err != nil {
		return err
	}
	if len(headers) == 0 {
		return nil
	}

	columns := make([]any, len(headers))
	for i, h := range headers {
		columns[i] = h
	}

	tbl := table.New(columns...).WithWriter(w)
	for _, rec := range records {
		row := make([]any, len(headers))
		for i, h := range headers {
			row[i] = renderers.StringifyCell(rec[h])
		}
		tbl = tbl.AddRow(row...)
	}

	tbl.Print()
	return nil
}
