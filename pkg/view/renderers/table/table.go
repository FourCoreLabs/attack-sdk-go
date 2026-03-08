package table

import (
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
	"github.com/rodaine/table"
)

type tableRenderer struct{}

var _ renderers.Renderer = (*tableRenderer)(nil)

func NewTableRender() renderers.Renderer {
	return &tableRenderer{}
}

func (r *tableRenderer) Render(w io.Writer, items []any, opts ...renderers.RendererOptFunc) error {
	opt := renderers.RendererOption{}
	for _, fn := range opts {
		fn(&opt)
	}

	if len(items) == 0 {
		return nil
	}

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
