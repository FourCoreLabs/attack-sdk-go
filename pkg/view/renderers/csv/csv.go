package csv

import (
	"encoding/csv"
	"io"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
)

type csvRenderer struct{}

func NewCsvRender() renderers.Renderer {
	return &csvRenderer{}
}

func (r *csvRenderer) Render(w io.Writer, items []any) error {
	headers, records, err := renderers.BuildRecords(items)
	if err != nil {
		return err
	}
	if len(headers) == 0 {
		return nil
	}

	writer := csv.NewWriter(w)
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, rec := range records {
		row := make([]string, len(headers))
		for i, h := range headers {
			row[i] = renderers.StringifyCell(rec[h])
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
